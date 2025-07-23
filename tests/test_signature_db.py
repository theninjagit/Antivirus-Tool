import os
import tempfile
import unittest
from nogui import MalwareSignatureDB

class TestMalwareSignatureDB(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sig_file1 = os.path.join(self.temp_dir.name, "pack1.txt")
        self.sig_file2 = os.path.join(self.temp_dir.name, "pack2.txt")

        with open(self.sig_file1, "w", encoding="utf-8") as f:
            f.write("abc123;TestMalwareA\n")
            f.write("   \n")                        # blank line
            f.write("no_delimiter_line\n")          # malformed
            f.write("abc123;DuplicateShouldReplace\n")  # duplicate (overwrites)
            f.write("def456;TestMalwareB\n")

        with open(self.sig_file2, "w", encoding="utf-8") as f:
            f.write("fff999;AnotherMalware\n")

        self.db = MalwareSignatureDB()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_signatures_counts_only_valid(self):
        self.db.load_signatures([self.sig_file1, self.sig_file2])
        # Unique hashes: abc123, def456, fff999
        self.assertEqual(self.db.signature_count, 3)

    def test_duplicate_last_value_wins(self):
        self.db.load_signatures([self.sig_file1])
        self.assertEqual(self.db.match_hash("abc123"), "DuplicateShouldReplace")

    def test_match_hash_existing(self):
        self.db.load_signatures([self.sig_file1])
        self.assertEqual(self.db.match_hash("def456"), "TestMalwareB")

    def test_match_hash_missing(self):
        self.db.load_signatures([self.sig_file1])
        self.assertIsNone(self.db.match_hash("does_not_exist"))

    def test_missing_file_is_skipped(self):
        # Only sig_file1 actually loads (2 valid unique hashes)
        self.db.load_signatures([self.sig_file1, os.path.join(self.temp_dir.name, "missing.txt")])
        self.assertEqual(self.db.signature_count, 2)


if __name__ == "__main__":
    unittest.main()
