import os
import json
import tempfile
import unittest
from pathlib import Path

from nogui import QuarantineManager


class TestQuarantineManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)
        self.quarantine_dir = self.base / "quarantine_area"
        self.db_file = self.base / "qdb.json"
        self.manager = QuarantineManager(str(self.quarantine_dir), str(self.db_file))

        self.source_file = self.base / "sample.txt"
        self.source_file.write_text("danger content", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_quarantine_file_moves_and_records(self):
        ok = self.manager.quarantine_file(str(self.source_file))
        self.assertTrue(ok)
        self.assertFalse(self.source_file.exists())
        files = list(self.quarantine_dir.iterdir())
        self.assertEqual(len(files), 1)
        quarantined_path = str(files[0])
        self.assertIn(quarantined_path, self.manager.quarantine_db)
        self.assertEqual(self.manager.quarantine_db[quarantined_path], str(self.source_file))

    def test_quarantine_name_collision(self):
        self.manager.quarantine_file(str(self.source_file))
        self.source_file.write_text("danger content again", encoding="utf-8")
        self.manager.quarantine_file(str(self.source_file))
        files = sorted(p.name for p in self.quarantine_dir.iterdir())
        self.assertTrue("sample.txt" in files)
        self.assertTrue(any(name.startswith("sample_1") for name in files))

    def test_delete_file_removes_entry(self):
        self.manager.quarantine_file(str(self.source_file))
        quarantined = list(self.quarantine_dir.iterdir())[0]
        ok = self.manager.delete_file(str(quarantined))
        self.assertTrue(ok)
        self.assertFalse(quarantined.exists())
        self.assertNotIn(str(quarantined), self.manager.quarantine_db)

    def test_database_persistence(self):
        self.manager.quarantine_file(str(self.source_file))
        with open(self.db_file, "r", encoding="utf-8") as f:
            data_before = json.load(f)
        self.assertEqual(len(data_before), 1)
        new_manager = QuarantineManager(str(self.quarantine_dir), str(self.db_file))
        self.assertEqual(len(new_manager.quarantine_db), 1)

    def test_quarantine_nonexistent_file(self):
        bogus = self.base / "nope.bin"
        ok = self.manager.quarantine_file(str(bogus))
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
