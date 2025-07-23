import os
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import tkinter.font as tkfont
import threading
import queue
from datetime import datetime
import json
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class MalwareSignatureDB:
    """Data Structure to store and manage malware signatures"""
    def __init__(self):
        self.signatures = {} # {hash: malware_name}
        self.signature_count = 0
    
    def load_signatures(self, signature_files):
        """Load signatures from multiple files"""
        for file_path in signature_files:
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        if ';' in line:
                            hash_val, malware_name = line.strip().split(';', 1)
                            self.signatures[hash_val] = malware_name
                            self.signature_count += 1
            except Exception as e:
                print(f"Error loading {file_path}: {str(e)}")
    
    def add_signature(self, hash_val, malware_name):
        if hash_val not in self.signatures:
            self.signatures[hash_val] = malware_name
            self.signature_count += 1
    
    def match_hash(self, file_hash):
        return self.signatures.get(file_hash, None)

class QuarantineManager:
    """Manages quarantined files with original path tracking"""
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        self.quarantine_db = {}  # {quarantined_path: original_path}
        self.load_quarantine_db()
        
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
    
    def load_quarantine_db(self):
        if os.path.exists("quarantine_db.json"):
            with open("quarantine_db.json", 'r') as f:
                self.quarantine_db = json.load(f)
    
    def save_quarantine_db(self):
        with open("quarantine_db.json", 'w') as f:
            json.dump(self.quarantine_db, f)
    
    def quarantine_file(self, file_path):
        """Move file to quarantine and track original location"""
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, file_name)
            
            # Ensure unique filename
            counter = 1
            while os.path.exists(quarantine_path):
                name, ext = os.path.splitext(file_name)
                quarantine_path = os.path.join(self.quarantine_dir, f"{name}_{counter}{ext}")
                counter += 1
            
            os.rename(file_path, quarantine_path)
            self.quarantine_db[quarantine_path] = file_path
            self.save_quarantine_db()
            return True
        except Exception as e:
            print(f"Quarantine error: {str(e)}")
            return False
    
    def restore_file(self, quarantine_path):
        """Restore file to original location"""
        if quarantine_path in self.quarantine_db:
            original_path = self.quarantine_db[quarantine_path]
            try:
                os.rename(quarantine_path, original_path)
                del self.quarantine_db[quarantine_path]
                self.save_quarantine_db()
                return True
            except Exception as e:
                print(f"Restore error: {str(e)}")
        return False
    
    def delete_file(self, quarantine_path):
        """Permanently delete quarantined file"""
        try:
            os.remove(quarantine_path)
            if quarantine_path in self.quarantine_db:
                del self.quarantine_db[quarantine_path]
                self.save_quarantine_db()
            return True
        except Exception as e:
            print(f"Delete error: {str(e)}")
            return False
    
    def get_quarantined_files(self):
        """Return list of quarantined files with original paths"""
        return [(q_path, self.quarantine_db.get(q_path, "Unknown")) 
                for q_path in os.listdir(self.quarantine_dir)]

class RealTimeMonitor(FileSystemEventHandler):
    """Watchdog-based real-time file system monitor"""
    def __init__(self, scanner, quarantine, log_callback):
        self.scanner = scanner
        self.quarantine = quarantine
        self.log_callback = log_callback
        self.running = False
        self.observer = Observer()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.scan_file(event.src_path)
    
    def scan_file(self, file_path):
        result = self.scanner.scan_file(file_path)
        if result and result['infected']:
            self.log_callback(f"Real-time detection: {file_path} infected with {result['threats']}")
            self.quarantine.quarantine_file(file_path)
            self.log_callback(f"Quarantined: {file_path}")
    
    def start(self, watch_paths):
        if not self.running:
            for path in watch_paths:
                if os.path.exists(path):
                    self.observer.schedule(self, path, recursive=True)
            self.observer.start()
            self.running = True
    
    def stop(self):
        if self.running:
            self.observer.stop()
            self.running = False
    
    def join(self):
        self.observer.join()

class AntivirusEngine:
    """Core scanning functionality"""
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.signature_db = MalwareSignatureDB()
        self.quarantine = QuarantineManager()
        self.realtime_monitor = RealTimeMonitor(self, self.quarantine, log_callback)
        self.scan_results = {}
        self.load_signatures()
    
    def log(self, message):
        if self.log_callback:
            self.log_callback(message)
    
    def load_signatures(self):
        """Load local signature databases"""
        sig_files = [
            "signatures/sha256_pack1.txt",
            "signatures/sha256_pack2.txt",
            "signatures/sha256_pack3.txt"
        ]
        self.signature_db.load_signatures(sig_files)
        self.log(f"Loaded {self.signature_db.signature_count} malware signatures")
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.log(f"Hash error for {file_path}: {str(e)}")
            return None
    
    def scan_file(self, file_path):
        """Scan a single file for malware"""
        try:
            file_hash = self.calculate_file_hash(file_path)
            if not file_hash:
                return None
            
            malware_name = self.signature_db.match_hash(file_hash)
            if malware_name:
                return {
                    'file': os.path.basename(file_path),
                    'path': file_path,
                    'hash': file_hash,
                    'infected': True,
                    'threats': [malware_name],
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'file': os.path.basename(file_path),
                'path': file_path,
                'hash': file_hash,
                'infected': False,
                'threats': [],
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.log(f"Scan error for {file_path}: {str(e)}")
            return None
    
    def scan_directory(self, directory_path, recursive=True):
        """Scan all files in a directory"""
        self.log(f"Scanning directory: {directory_path}")
        scan_results = {
            'directory': directory_path,
            'total_files': 0,
            'infected_files': 0,
            'threats_found': set(),
            'files': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            for root, _, files in os.walk(directory_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    try:
                        # Skip directories and unreadable files
                        if not os.path.isfile(file_path):
                            continue
                            
                        scan_results['total_files'] += 1
                        result = self.scan_file(file_path)
                        
                        if result:
                            scan_results['files'].append(result)
                            if result['infected']:
                                scan_results['infected_files'] += 1
                                scan_results['threats_found'].update(result['threats'])
                    
                    except (PermissionError, OSError) as e:
                        self.log(f"Skipping {file_path}: {str(e)}")
                    
                if not recursive:
                    break
            
            self.scan_results[directory_path] = scan_results
            return scan_results
        except Exception as e:
            self.log(f"Directory scan error: {str(e)}")
            return None
    
    def start_realtime_monitoring(self, watch_paths=None):
        """Start real-time file system monitoring"""
        if not watch_paths:
            watch_paths = [
                os.path.expanduser("~/.local/bin"),
                os.path.expanduser("~/.config/autostart"),
                "/tmp"
            ]
        self.realtime_monitor.start(watch_paths)
        self.log(f"Started real-time monitoring on: {', '.join(watch_paths)}")
    
    def stop_realtime_monitoring(self):
        """Stop real-time monitoring"""
        self.realtime_monitor.stop()
        self.log("Stopped real-time monitoring")

class AntivirusGUI:
    """Main application GUI"""
    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirus")
        self.root.geometry("1000x700")
        
        # Create message queue for thread-safe logging
        self.log_queue = queue.Queue()
        
        # Create antivirus engine
        self.antivirus = AntivirusEngine(log_callback=self.log_message)
        self.scan_thread = None
        self.stop_scan_flag = False
        
        # Create UI components
        self.create_menu()
        self.create_main_container()
        
        # Start log monitor
        self.monitor_logs()
        
        # Start real-time monitoring
        self.antivirus.start_realtime_monitoring()
    
    def log_message(self, message):
        """Add message to log queue"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"{timestamp} - {message}")
    
    def monitor_logs(self):
        """Update log display from queue"""
        while True:
            try:
                message = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
            except queue.Empty:
                break
        self.root.after(100, self.monitor_logs)
    
    def create_menu(self):
        menubar = Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan Menu
        scan_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Quick Scan", command=self.quick_scan)
        scan_menu.add_command(label="Full Scan", command=self.full_scan)
        scan_menu.add_command(label="Custom Scan", command=self.custom_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Scan File", command=self.scan_file)
        
        # Quarantine Menu
        quarantine_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Quarantine", menu=quarantine_menu)
        quarantine_menu.add_command(label="View Quarantine", command=self.show_quarantine)
        quarantine_menu.add_command(label="Clean Quarantine", command=self.clean_quarantine)
        
        # Help Menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_main_container(self):
        # Create main container with padding
        self.main_container = ttk.Frame(self.root, padding="20")
        self.main_container.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)
        
        # Create header
        self.create_header()
        
        # Create scan panels
        self.create_scan_panels()
        
        # Create log panel
        self.create_log_panel()
    
    def create_header(self):
        header_frame = ttk.Frame(self.main_container)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        # Title
        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        title_label = ttk.Label(header_frame, text="Python Antivirus", font=title_font)
        title_label.grid(row=0, column=0, sticky="w")
        
        # Control buttons
        control_frame = ttk.Frame(header_frame)
        control_frame.grid(row=0, column=1, sticky="e")
        
        self.scan_button = ttk.Button(control_frame, text="Start Scan", 
                                    command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Scan", 
                                    command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, padx=5)
    
    def create_scan_panels(self):
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(self.main_container)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(0, 20))
        
        # Quick Scan Tab
        quick_frame = ttk.Frame(notebook, padding="10")
        notebook.add(quick_frame, text="Quick Scan")
        self.create_quick_scan_panel(quick_frame)
        
        # Full Scan Tab
        full_frame = ttk.Frame(notebook, padding="10")
        notebook.add(full_frame, text="Full Scan")
        self.create_full_scan_panel(full_frame)
        
        # Custom Scan Tab
        custom_frame = ttk.Frame(notebook, padding="10")
        notebook.add(custom_frame, text="Custom Scan")
        self.create_custom_scan_panel(custom_frame)
    
    def create_quick_scan_panel(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Quick scan checks common infection locations").pack(pady=5)
        ttk.Button(frame, text="Run Quick Scan", 
                 command=self.quick_scan).pack(pady=20)
    
    def create_full_scan_panel(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        
        ttk.Label(frame, text="Full system scan (may take a while)").pack(pady=5)
        ttk.Button(frame, text="Run Full Scan", 
                 command=self.full_scan).pack(pady=20)
    
    def create_custom_scan_panel(self, parent):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        
        # Directory selection
        ttk.Label(frame, text="Select Directory to Scan:").pack(pady=5)
        
        self.custom_scan_path = ttk.Entry(frame, width=50)
        self.custom_scan_path.pack(pady=5, padx=10, side="left", fill="x", expand=True)
        
        ttk.Button(frame, text="Browse...", 
                 command=self.browse_custom_scan).pack(pady=5, padx=5, side="left")
        
        # Scan button
        ttk.Button(frame, text="Run Custom Scan", 
                 command=self.custom_scan).pack(pady=20)
    
    def create_log_panel(self):
        log_frame = ttk.LabelFrame(self.main_container, text="Scan Logs")
        log_frame.grid(row=2, column=0, sticky="nsew")
        
        # Log display
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=100)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Log controls
        control_frame = ttk.Frame(log_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Save Logs", command=self.save_logs).pack(side="left", padx=5)
    
    def browse_custom_scan(self):
        directory = filedialog.askdirectory()
        if directory:
            self.custom_scan_path.delete(0, tk.END)
            self.custom_scan_path.insert(0, directory)
    
    def clear_logs(self):
        self.log_text.delete(1.0, tk.END)
    
    def save_logs(self):
        try:
            with open("antivirus_logs.txt", "w") as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "Logs saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def quick_scan(self):
        """Scan common infection locations"""
        common_paths = [
            os.path.expanduser("~/.local/bin"),
            os.path.expanduser("~/.config/autostart"),
            "/tmp"
        ]
        self.start_scan(common_paths)
    
    def full_scan(self):
        """Scan entire filesystem"""
        self.start_scan(["/"])
    
    def custom_scan(self):
        """Scan user-selected directory"""
        directory = self.custom_scan_path.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory to scan")
            return
        self.start_scan([directory])
    
    def scan_file(self):
        """Scan single file"""
        file_path = filedialog.askopenfilename()
        if file_path:
            result = self.antivirus.scan_file(file_path)
            if result:
                if result['infected']:
                    self.handle_infected_file(file_path, result['threats'])
                else:
                    self.log_message(f"No threats found in {file_path}")
    
    def handle_infected_file(self, file_path, threats):
        """Show options when a virus is detected"""
        action = messagebox.askquestion(
            "Virus Detected",
            f"Threat found in {os.path.basename(file_path)}:\n{', '.join(threats)}\n\n"
            "Quarantine this file? (No will delete it permanently)",
            icon='warning'
        )
        
        if action == 'yes':
            if self.antivirus.quarantine.quarantine_file(file_path):
                self.log_message(f"Quarantined: {file_path}")
            else:
                self.log_message(f"Failed to quarantine: {file_path}")
        else:
            if self.antivirus.quarantine.delete_file(file_path):
                self.log_message(f"Deleted: {file_path}")
            else:
                self.log_message(f"Failed to delete: {file_path}")
    
    def start_scan(self, paths):
        """Start scanning in background thread"""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Warning", "Scan already in progress")
            return
        
        self.stop_scan_flag = False
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        def scan_task():
            for path in paths:
                if self.stop_scan_flag:
                    break
                self.antivirus.scan_directory(path)
            self.scan_complete()
        
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Request scan to stop"""
        self.stop_scan_flag = True
        self.log_message("Scan stopping...")
    
    def scan_complete(self):
        """Clean up after scan completes"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_message("Scan completed")
    
    def show_quarantine(self):
        """Display quarantined files"""
        quarantine_window = tk.Toplevel(self.root)
        quarantine_window.title("Quarantine Manager")
        quarantine_window.geometry("600x400")
        
        frame = ttk.Frame(quarantine_window, padding="10")
        frame.pack(fill="both", expand=True)
        
        # Quarantined files list
        ttk.Label(frame, text="Quarantined Files:").pack(pady=5)
        
        self.quarantine_list = ttk.Treeview(frame, columns=("File", "Original Path"))
        self.quarantine_list.heading("#0", text="ID")
        self.quarantine_list.heading("File", text="File")
        self.quarantine_list.heading("Original Path", text="Original Path")
        self.quarantine_list.pack(fill="both", expand=True, pady=5)
        
        # Populate list
        for idx, (q_file, orig_path) in enumerate(self.antivirus.quarantine.get_quarantined_files()):
            self.quarantine_list.insert("", "end", text=str(idx+1), 
                                      values=(os.path.basename(q_file), orig_path))
        
        # Action buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="Restore", 
                  command=lambda: self.quarantine_action("restore")).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Delete", 
                  command=lambda: self.quarantine_action("delete")).pack(side="left", padx=5)
    
    def quarantine_action(self, action):
        """Handle quarantine restore/delete actions"""
        selected = self.quarantine_list.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        item = self.quarantine_list.item(selected[0])
        file_name = item['values'][0]
        
        if action == "restore":
            if messagebox.askyesno("Confirm", f"Restore {file_name} to original location?"):
                # Implementation would restore the file
                messagebox.showinfo("Info", "Restore functionality would be implemented here")
        elif action == "delete":
            if messagebox.askyesno("Confirm", f"Permanently delete {file_name}?"):
                # Implementation would delete the file
                messagebox.showinfo("Info", "Delete functionality would be implemented here")
    
    def clean_quarantine(self):
        """Delete all quarantined files"""
        if messagebox.askyesno("Confirm", "Permanently delete ALL quarantined files?"):
            # Implementation would clean quarantine
            messagebox.showinfo("Info", "Clean quarantine functionality would be implemented here")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", 
                          "Python Antivirus\n"
                          "Version 1.0\n\n"
                          "A local malware detection system\n"
                          "using signature-based scanning.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusGUI(root)
    try:
        root.mainloop()
    finally:
        app.antivirus.stop_realtime_monitoring()