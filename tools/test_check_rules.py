"""Small, offline regression tests for the all-rules harness itself."""
import json
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import check_rules as rules

PROJECT = pathlib.Path(__file__).resolve().parent.parent


class RuleHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = pathlib.Path(self.tmp.name)
        self.events, self.alerts = base / 'events.jsonl', base / 'alerts.jsonl'
        self.runner = rules.Live(SimpleNamespace(namespace='security-lab', kubectl=None), PROJECT, base / 'results')
        self.runner.events, self.runner.alerts = self.events, self.alerts

    def write(self, events, alerts):
        self.events.write_text(''.join(json.dumps(e) + '\n' for e in events))
        self.alerts.write_text(''.join(json.dumps(a) + '\n' for a in alerts))

    @staticmethod
    def event(event_id, event_type, *, binary='/bin/sh', path=None, ip=None, exec_id='same', at='2026-11-21T10:00:01Z', pod='test-pod'):
        e = {'event_id': event_id, 'event_type': event_type, 'timestamp': at,
             'node': 'lab-node', 'kubernetes': {'namespace': 'security-lab', 'pod': pod,
             'pod_uid': 'pod-uid', 'container_id': 'container-id'},
             'process': {'binary': binary, 'exec_id': exec_id, 'parent_exec_id': ''}}
        if path is not None:
            e['file'] = {'path': path}
        if ip is not None:
            e['network'] = {'destination_ip': ip, 'destination_port': 443}
        return e

    @staticmethod
    def alert(rule, *ids):
        return {'rule_id': rule, 'kubernetes': {'pod': 'test-pod'}, 'related_event_ids': list(ids),
                'emitted_at': '2026-11-21T10:00:04Z'}

    def test_22_rules_and_fixture_shape(self):
        self.assertEqual(len(rules.read_rules(PROJECT)), 22)
        f = rules.ReplayFactory()
        for rid in rules.ALL:
            f.case(rid, True)
            f.case(rid, False)
        self.assertEqual(len(f.cases), 44)
        self.assertEqual(len({c['test_id'] for c in f.cases}), 44)

    def test_pass_requires_linked_event(self):
        e = self.event('e1', 'process.exec')
        self.write([e], [self.alert('R001', 'e1')])
        result = self.runner.scan_case('test-pod', 'R001', [{'event_type': 'process.exec', 'binary': '/bin/sh'}])
        self.assertEqual(result['status'], 'PASS')
        self.write([e], [self.alert('R001', 'not-an-event')])
        result = self.runner.scan_case('test-pod', 'R001', [{'event_type': 'process.exec', 'binary': '/bin/sh'}])
        self.assertEqual(result['status'], 'FAIL_RULE')

    def test_missing_telemetry_is_not_a_negative_classification(self):
        self.write([], [])
        result = self.runner.scan_case('test-pod', 'R010', [{'event_type': 'file.access', 'path_suffix': '/token'}])
        self.assertEqual(result['status'], 'FAIL_TELEMETRY')

    def test_r007_require_same_process_and_timestamp_order(self):
        f = self.event('file1', 'file.access', path='/var/run/secrets/kubernetes.io/serviceaccount/token')
        n = self.event('net1', 'network.connect', ip='1.1.1.1', at='2026-11-21T10:00:02Z')
        expected = [{'event_type': 'file.access', 'path_suffix': '/token'},
                    {'event_type': 'network.connect', 'ip': '1.1.1.1'}]
        self.write([f, n], [self.alert('R007', 'file1', 'net1')])
        self.assertEqual(self.runner.scan_case('test-pod', 'R007', expected)['status'], 'PASS')
        n['process']['exec_id'] = 'different'
        self.write([f, n], [])
        result = self.runner.scan_case('test-pod', 'R007', expected)
        self.assertEqual(result['status'], 'FAIL_PRECONDITION')
        self.assertIn('exec_id', result['precondition_reason'])

    def test_r021_requires_all_five_distinct_source_events(self):
        events = [self.event(f'e{i}', 'network.connect', ip=f'10.42.1.{i}') for i in range(1, 6)]
        expected = [{'event_type': 'network.connect', 'ip': f'10.42.1.{i}'} for i in range(1, 6)]
        self.write(events, [self.alert('R021', 'e1', 'e2', 'e3', 'e4')])
        self.assertEqual(self.runner.scan_case('test-pod', 'R021', expected)['status'], 'FAIL_RULE')
        self.write(events, [self.alert('R021', 'e1', 'e2', 'e3', 'e4', 'e5')])
        self.assertEqual(self.runner.scan_case('test-pod', 'R021', expected)['status'], 'PASS')

    def test_report_isolated_per_pod(self):
        matching = self.event('e1', 'process.exec', pod='another-pod')
        self.write([matching], [self.alert('R001', 'e1')])
        self.assertEqual(self.runner.scan_case('test-pod', 'R001', [{'event_type': 'process.exec', 'binary': '/bin/sh'}])['status'], 'FAIL_TELEMETRY')


if __name__ == '__main__':
    unittest.main()
