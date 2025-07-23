import os
import time
import shutil
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class MalwareSignatureDB:
    """Data Structure to store and manage malware signatures."""
    def __init__(self) -> None:
        self.signatures: Dict[str, str] = {}

    def load_signatures(self, signature_files: List[str]) -> None:
        for file_path in signature_files:
            if not os.path.exists(file_path):
                print(f"Signature file missing: {file_path}")
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or ';' not in line:
                            continue
                        hash_val, malware_name = line.split(';', 1)
                        self.signatures[hash_val.strip()] = malware_name.strip()
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

    def match_hash(self, file_hash: str) -> Optional[str]:
        return self.signatures.get(file_hash)

    @property
    def signature_count(self) -> int:
        return len(self.signatures)


class QuarantineManager:
    """Manages quarantined files with original path tracking."""
    def __init__(self, quarantine_dir: str = "quarantine", db_file: str = "quarantine_db.json") -> None:
        self.quarantine_dir = quarantine_dir
        self.db_file = db_file
        self.quarantine_db: Dict[str, str] = {}
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.load_quarantine_db()

    def load_quarantine_db(self) -> None:
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    self.quarantine_db = json.load(f)
            except Exception as e:
                print(f"Could not load quarantine DB: {e}")

    def save_quarantine_db(self) -> None:
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(self.quarantine_db, f, indent=2)
        except Exception as e:
            print(f"Could not save quarantine DB: {e}")

    def quarantine_file(self, file_path: str) -> bool:
        if not os.path.isfile(file_path):
            print(f"Cannot quarantine (not a file): {file_path}")
            return False
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, file_name)
            base_name, ext = os.path.splitext(file_name)
            counter = 1
            while os.path.exists(quarantine_path):
                quarantine_path = os.path.join(self.quarantine_dir, f"{base_name}_{counter}{ext}")
                counter += 1
            shutil.move(file_path, quarantine_path)
            self.quarantine_db[quarantine_path] = file_path
            self.save_quarantine_db()
            return True
        except Exception as e:
            print(f"Quarantine error: {e}")
            return False

    def delete_file(self, quarantine_path: str) -> bool:
        try:
            os.remove(quarantine_path)
            self.quarantine_db.pop(quarantine_path, None)
            self.save_quarantine_db()
            return True
        except Exception as e:
            print(f"Delete error: {e}")
            return False


class RealTimeMonitor(FileSystemEventHandler):
    """Watchdog-based real-time file system monitor."""
    def __init__(self, scanner: 'AntivirusEngine', quarantine: QuarantineManager) -> None:
        super().__init__()
        self.scanner = scanner
        self.quarantine = quarantine
        self.observer = Observer()
        self.running = False

    def on_modified(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)

    def scan_file(self, file_path: str):
        result = self.scanner.scan_file(file_path)
        if result and result['infected']:
            print(f"Real-time detection: {file_path} infected with {', '.join(result['threats'])}")
            self.quarantine.quarantine_file(file_path)

    def start(self, watch_paths: List[str]):
        if self.running:
            print("Real-time monitoring already running.")
            return
        for path in watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self, path, recursive=True)
        self.observer.start()
        self.running = True
        print(f"Started real-time monitoring on: {', '.join(watch_paths)}")

    def stop(self):
        if self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            print("Stopped real-time monitoring.")


class AntivirusEngine:
    """Core scanning functionality."""
    def __init__(self):
        self.signature_db = MalwareSignatureDB()
        self.quarantine = QuarantineManager()
        self.realtime_monitor = RealTimeMonitor(self, self.quarantine)
        self.load_signatures()

    def load_signatures(self):
        sig_files = [
            "signatures/sha256_pack1.txt",
            "signatures/sha256_pack2.txt",
            "signatures/sha256_pack3.txt"
        ]
        self.signature_db.load_signatures(sig_files)
        print(f"Loaded {self.signature_db.signature_count} malware signatures.")

    @staticmethod
    def calculate_file_hash(file_path: str) -> Optional[str]:
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Hash error for {file_path}: {e}")
            return None

    def scan_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(file_path):
            return None
        file_hash = self.calculate_file_hash(file_path)
        malware_name = self.signature_db.match_hash(file_hash) if file_hash else None
        return {
            'file': os.path.basename(file_path),
            'path': file_path,
            'hash': file_hash,
            'infected': bool(malware_name),
            'threats': [malware_name] if malware_name else [],
            'timestamp': datetime.now().isoformat()
        }

    def scan_directory(self, directory_path: str, recursive: bool = True):
        if not os.path.isdir(directory_path):
            print(f"Not a directory: {directory_path}")
            return None
        print(f"Scanning directory: {directory_path}")
        total_files = 0
        infected_files = 0
        threats_found = set()
        for root, _, files in os.walk(directory_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                result = self.scan_file(file_path)
                if result:
                    total_files += 1
                    if result['infected']:
                        infected_files += 1
                        threats_found.update(result['threats'])
                        print(f"Found threat in {file_path}: {', '.join(result['threats'])}")
            if not recursive:
                break
        print(f"\nScan completed for {directory_path}")
        print(f"Files scanned: {total_files}")
        print(f"Infected files found: {infected_files}")
        if threats_found:
            print("Threats detected:")
            for threat in threats_found:
                print(f" - {threat}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Python Antivirus Scanner")
    parser.add_argument('--scan', help="Directory or file to scan")
    parser.add_argument('--quick', action='store_true', help="Run quick scan (Windows user dirs)")
    parser.add_argument('--full', action='store_true', help="Run full system scan")
    parser.add_argument('--realtime', action='store_true', help="Enable real-time monitoring")
    args = parser.parse_args()

    av = AntivirusEngine()

    if args.scan:
        if os.path.isfile(args.scan):
            result = av.scan_file(args.scan)
            if result and result['infected']:
                print(f"Threat found in {args.scan}: {', '.join(result['threats'])}")
                action = input("Quarantine this file? (y=quarantine / d=delete / other=ignore): ").lower()
                if action == 'y':
                    av.quarantine.quarantine_file(args.scan)
                elif action == 'd':
                    os.remove(args.scan)
            else:
                print("No threats found.")
        elif os.path.isdir(args.scan):
            av.scan_directory(args.scan)
        else:
            print("Invalid path specified.")
    elif args.quick:
        print("Running quick scan...")
        user_dir = os.path.expanduser("~")
        quick_paths = [
            os.path.join(user_dir, "Desktop"),
            os.path.join(user_dir, "Downloads"),
            os.path.join(user_dir, "Documents"),
            "C:\\Windows\\Temp"
        ]
        for path in quick_paths:
            if os.path.isdir(path):
                av.scan_directory(path)
            else:
                print(f"Not a directory: {path}")
    elif args.full:
        print("Running full system scan... (may take a long time)")
        av.scan_directory("C:\\", recursive=True)
    elif args.realtime:
        print("Starting real-time monitoring (Ctrl+C to stop)...")
        av.realtime_monitor.start(["C:\\Users", "C:\\Windows\\Temp"])
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            av.stop_realtime_monitoring()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
