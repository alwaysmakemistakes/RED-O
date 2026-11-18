import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import performance_benchmark as p


class PerformanceBenchmarkTests(unittest.TestCase):
    def test_quantiles(self):
        self.assertIsNone(p.quantile([], 95))
        self.assertEqual(p.quantile([5], 99), 5)
        self.assertEqual(p.quantile([1, 2, 3, 4, 5], 50), 3)
        self.assertAlmostEqual(p.quantile([1, 2, 3, 4, 5], 95), 4.8)

    def test_parse_prometheus(self):
        values = p.parse_prometheus('# HELP ignored\nredo_events_normalized_total 234\nredo_test{pod="a"} 1\n')
        self.assertEqual(values, {'redo_events_normalized_total': 234.0})

    def test_workload_has_bounded_iterations(self):
        script = p.workload_script(5, 4)
        self.assertIn('"$n" -lt 20', script)
        self.assertIn('cat /etc/passwd >/dev/null', script)

    def test_process_sample_self(self):
        sample = p.process_sample(__import__('os').getpid())
        self.assertGreater(sample['rss_bytes'], 0)
        self.assertGreaterEqual(sample['cpu_seconds'], 0)

    def test_process_summary(self):
        report = p.summarize_process([(1, {'rss_bytes': 1024, 'cpu_seconds': 1}),
                                      (2, {'rss_bytes': 2048, 'cpu_seconds': 1.25})])
        self.assertEqual(report['cpu_percent_one_core']['p50'], 25)


if __name__ == '__main__':
    unittest.main()

class LiveHarnessUnitTests(unittest.TestCase):
    def test_read_alert_ids_across_segment(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'alerts.jsonl'
            record = {'alert_id': 'a1', 'rule_id': 'R007',
                      'kubernetes': {'namespace': 'security-lab', 'pod': 'token-probe'}}
            (Path(d) / 'alerts.jsonl.segment-01').write_text(json.dumps(record) + '\n')
            path.write_text('{incomplete\n')
            self.assertEqual(p.alert_ids(path, 'R007', 'security-lab', 'token-probe'), {'a1'})

    def test_mocked_live_load_creates_json_and_csv(self):
        import argparse
        import tempfile
        from unittest.mock import patch
        import subprocess
        import os
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(namespace='security-lab', pod='ebpf-test',
                                      rate=2, duration=1, settle=0, sample_interval=.05,
                                      detector_pid=os.getpid(), web_pid=None,
                                      metrics='http://localhost:9095/metrics',
                                      output=Path(directory) / 'load.json')
            before = {'redo_events_received_total': 10., 'redo_events_normalized_total': 9.}
            after = {'redo_events_received_total': 14., 'redo_events_normalized_total': 13.}
            fake = subprocess.CompletedProcess([], 0, 'REDO_COMPLETED=2\n', '')
            with patch.object(p, 'require_pod'), patch.object(p, 'get_metrics', side_effect=[before, after]), \
                 patch.object(p, 'find_process', return_value=None), \
                 patch.object(p.subprocess, 'run', return_value=fake):
                report = p.run_load(args)
            self.assertEqual(report['metric_deltas']['redo_events_normalized_total'], 4)
            self.assertTrue(args.output.is_file())
            self.assertTrue(args.output.with_suffix('.csv').is_file())

class V091RegressionTests(unittest.TestCase):
    def test_managed_pid_rejects_stale(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'detector.pid').write_text(f'{os.getpid()}\n')
            self.assertIsNone(p.managed_pid('detector', Path(d)))
            (Path(d) / 'detector.pid').write_text('garbage')
            self.assertIsNone(p.managed_pid('detector', Path(d)))

    def test_managed_pid_reads_cli_child(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'detector.pid').write_text('1234\n')
            read_bytes = Path.read_bytes
            read_text = Path.read_text
            def fake_bytes(path):
                if str(path) == '/proc/1234/cmdline':
                    return b'/home/main/RED-O/bin/red-o\0__detector-run\0'
                return read_bytes(path)
            def fake_text(path, *args, **kwargs):
                if str(path) == '/proc/1234/stat':
                    return '1234 (red-o) S ' + '0 ' * 30
                return read_text(path, *args, **kwargs)
            with patch.object(Path, 'read_bytes', fake_bytes), patch.object(Path, 'read_text', fake_text):
                self.assertEqual(p.managed_pid('detector', Path(d)), 1234)
                self.assertIsNone(p.managed_pid('web', Path(d)))

    def test_burst_mode_avoids_sleep(self):
        self.assertNotIn('sleep ', p.workload_script(10, 2, 'burst'))
        self.assertIn('sleep ', p.workload_script(10, 2, 'paced'))

    def test_sweep_summary_stats(self):
        runs = [dict(target_rate=5, completed_actions=10, failed_actions=0,
                     actual_actions_per_second=x, normalized_eps=x*4,
                     detector_cpu_p95=4, detector_rss_p95_bytes=1024,
                     web_cpu_p95=1, web_rss_p95_bytes=2048) for x in (4,6)]
        rows = p.summarize_sweep(runs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['normalized_eps_mean'], 20)
        self.assertEqual(rows[0]['completed_actions'], 20)
        self.assertGreater(rows[0]['normalized_eps_stddev'], 0)

class PlotSmokeTests(unittest.TestCase):
    def test_svg_generated_without_external_dependencies(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / 'sweep.svg'
            p.plot_summary_svg([{'target_rate': 5, 'normalized_eps_mean': 30,
                                 'detector_cpu_p95_mean': 8,
                                 'detector_rss_p95_bytes_mean': 2_097_152}], dest)
            text = dest.read_text()
            self.assertIn('<svg', text)
            self.assertIn('30.00', text)
            self.assertIn('2.00', text)
