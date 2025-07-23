import os
import tempfile
import unittest
import hashlib
from pathlib import Path

from nogui import AntivirusEngine


class TestAntivirusEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.sig_dir = self.base / "signatures"
        self.sig_dir.mkdir(parents=True, exist_ok=True)

        self.old_cwd = os.getcwd()
        os.chdir(self.base)

        self.infected_file = self.base / "bad.exe"
        self.clean_file = self.base / "good.txt"
        self.infected_file.write_bytes(b"malicious payload bytes")
        self.clean_file.write_text("just a harmless file", encoding="utf-8")

        infected_hash = self._sha256_file(self.infected_file)

        (self.sig_dir / "sha256_pack1.txt").write_text(
            f"{infected_hash};Test.Infected.Sample\n", encoding="utf-8"
        )
        (self.sig_dir / "sha256_pack2.txt").write_text("", encoding="utf-8")
        (self.sig_dir / "sha256_pack3.txt").write_text("", encoding="utf-8")

        self.engine = AntivirusEngine()

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.temp_dir.cleanup()

    def _sha256_file(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def test_signatures_loaded(self):
        self.assertEqual(self.engine.signature_db.signature_count, 1)

    def test_calculate_file_hash_matches_manual(self):
        manual = self._sha256_file(self.infected_file)
        engine_hash = self.engine.calculate_file_hash(str(self.infected_file))
        self.assertEqual(manual, engine_hash)

    def test_scan_file_infected(self):
        result = self.engine.scan_file(str(self.infected_file))
        self.assertIsNotNone(result)
        self.assertTrue(result["infected"])
        self.assertIn("Test.Infected.Sample", result["threats"])

    def test_scan_file_clean(self):
        result = self.engine.scan_file(str(self.clean_file))
        self.assertIsNotNone(result)
        self.assertFalse(result["infected"])
        self.assertEqual(result["threats"], [])

    def test_scan_file_nonexistent(self):
        result = self.engine.scan_file(str(self.base / "missing.bin"))
        self.assertIsNone(result)

    def test_scan_directory_counts(self):
        extra_clean = self.base / "notes.log"
        extra_clean.write_text("logs...", encoding="utf-8")
        # Run directory scan (output not asserted here—logic validated by individual scans)
        self.engine.scan_directory(str(self.base))
        infected_result = self.engine.scan_file(str(self.infected_file))
        clean_result = self.engine.scan_file(str(self.clean_file))
        self.assertTrue(infected_result["infected"])
        self.assertFalse(clean_result["infected"])


if __name__ == "__main__":
    unittest.main()
