import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import release_smoke as smoke

class ReleaseSmokeTests(unittest.TestCase):
    def test_expected_counts(self):
        smoke.assert_counts({'tp': 14, 'fp': 7, 'fn': 7, 'tn': 7}, smoke.EXPECTED_BASELINE)
        with self.assertRaisesRegex(ValueError, 'fp expected'):
            smoke.assert_counts({'tp': 14, 'fp': 8, 'fn': 7, 'tn': 7}, smoke.EXPECTED_BASELINE)

    def test_output_directory_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp)
            (p / 'out').mkdir()
            with self.assertRaisesRegex(ValueError, 'refusing to overwrite'):
                smoke.run_release_smoke(p, p / 'out', skip_go_tests=True, skip_watermark=True)

if __name__ == '__main__':
    unittest.main()
