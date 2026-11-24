import datetime as dt
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('quality_live_runner', pathlib.Path(__file__).with_name('quality_live_runner.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunnerTest(unittest.TestCase):
    def test_selector_requires_strong_evidence(self):
        t = dict(id='A', scenario='commands', label='positive', command=['true'],
                 selector={'event_type': 'process.exec', 'kubernetes.pod': 'x'}, enabled=True)
        with self.assertRaisesRegex(ValueError, 'specific action'):
            runner.validate_trial(t)
        t['selector']['process.arguments_contains'] = 'marker'
        runner.validate_trial(t)

    def test_matching_and_collection(self):
        stamp = '2026-11-21T18:00:00Z'
        trial = {'action_started_at': stamp, 'action_finished_at': stamp,
                 'selector': {'event_type': 'process.exec', 'kubernetes.pod': 'test',
                              'process.arguments_contains': 'unique-marker'}}
        records = [
            {'timestamp': stamp, 'event_id': 'A', 'event_type': 'process.exec',
             'kubernetes': {'pod': 'test'}, 'process': {'arguments': 'unique-marker'}},
            {'timestamp': stamp, 'event_id': 'B', 'event_type': 'process.exec',
             'kubernetes': {'pod': 'other'}, 'process': {'arguments': 'unique-marker'}},
        ]
        self.assertEqual(runner.select_evidence(records, trial, 1), ['A'])

    def test_dry_run_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            plan = root / 'plan.json'
            plan.write_text(json.dumps({'schema_version': '1.0', 'trials': [{
                'id': 'T1', 'scenario': 'commands', 'label': 'negative',
                'command': ['false'], 'selector': {'event_type': 'process.exec',
                   'process.arguments_contains': 'marker'}, 'enabled': True}]}))
            with patch.object(runner.subprocess, 'run', side_effect=AssertionError('executed')):
                self.assertEqual(runner.run(str(plan), str(root/'out'), str(root/'missing'),
                                            False, 0, 0, 1, None, None, 'suite.json'), 0)
            self.assertFalse((root/'out').exists())

    def test_successful_action_without_capture_remains_missing(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            plan = root / 'plan.json'
            events = root / 'events.jsonl'
            events.write_text(json.dumps({'event_id': 'other', 'event_type': 'process.exec',
                                          'timestamp': runner.utcnow(), 'process': {'arguments':'unrelated'}})+'\n')
            plan.write_text(json.dumps({'schema_version':'1.0','trials':[{
                'id':'T1','scenario':'commands','label':'positive','enabled':True,
                'command':['true'],'selector':{'event_type':'process.exec',
                                            'process.arguments_contains':'marker'},'expected_events':1}]}))
            self.assertEqual(runner.run(str(plan),str(root/'out'),str(events),True,0,1,10,None,None,'suite.json'),0)
            m=json.loads((root/'out'/'trials.json').read_text())
            self.assertEqual(m['trials'][0]['event_ids'], [])
            self.assertEqual(m['trials'][0]['action_status'], 'completed')

if __name__ == '__main__':
    unittest.main()
