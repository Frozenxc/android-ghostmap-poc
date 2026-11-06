import os
import tempfile
import unittest

from ghostmap.generator import GhostMapGenerator
from ghostmap.zip_utils import parse_zip_file
from ghostmap.analyzer import check_libziparchive, check_libandroidfw, ParserStatus
from ghostmap.remediation import sanitize_apk


class TestGhostMap(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_poc_generation_triggers_ghostmap(self):
        poc = os.path.join(self.tmpdir.name, "poc.apk")
        GhostMapGenerator.generate(poc, "resources.arsc", 99, 16 * 1024 * 1024)

        self.assertTrue(os.path.exists(poc))
        self.assertLess(os.path.getsize(poc), 50000)

        entries, cd_offset = parse_zip_file(poc)
        target = next((e for e in entries if e.filename == b"resources.arsc"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target.compression_method, 99)
        self.assertEqual(target.uncompressed_size, 16 * 1024 * 1024)

        zs, _ = check_libziparchive(target.compression_method, target.data_offset, target.uncompressed_size, cd_offset)
        self.assertEqual(zs, ParserStatus.OK)

        fs, _ = check_libandroidfw(target.compression_method, target.data_offset, target.uncompressed_size, os.path.getsize(poc))
        self.assertEqual(fs, ParserStatus.SIGBUS)

    def test_sanitizer_neutralizes_ghostmap(self):
        poc = os.path.join(self.tmpdir.name, "poc.apk")
        clean = os.path.join(self.tmpdir.name, "clean.apk")

        GhostMapGenerator.generate(poc, "resources.arsc", 99, 8 * 1024 * 1024)
        modified, count = sanitize_apk(poc, clean)
        self.assertTrue(modified)
        self.assertEqual(count, 1)

        entries, _ = parse_zip_file(clean)
        target = next((e for e in entries if e.filename == b"resources.arsc"), None)
        self.assertEqual(target.compression_method, 0)
        self.assertEqual(target.uncompressed_size, target.compressed_size)

        fs, _ = check_libandroidfw(target.compression_method, target.data_offset, target.uncompressed_size, os.path.getsize(clean))
        self.assertEqual(fs, ParserStatus.OK)


if __name__ == "__main__":
    unittest.main()
