import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from tools.ascend_flow.trace_import import import_trace


class TraceImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'trace.json'

    def load(self, events, **kwargs):
        self.path.write_text(json.dumps(events), encoding='utf-8')
        return import_trace(self.path, **kwargs)

    def codes(self, result):
        return {item['code'] for item in result['diagnostics']}

    def test_complete_metadata_and_flow_are_observations(self):
        raw = {'buffer': 4, 'eventID': 'opaque'}
        result = self.load({'traceEvents': [
            {'ph': 'M', 'name': 'thread_name', 'pid': 1, 'tid': 2, 'args': {'name': 'MTE2 raw'}},
            {'ph': 'X', 'name': 'SetFlag event7', 'pid': 1, 'tid': 2, 'ts': 12, 'dur': 3, 'args': raw},
            {'ph': 's', 'name': 'edge', 'pid': 1, 'tid': 2, 'ts': 13, 'id': 'f1'},
        ]}, time_unit='us')
        self.assertEqual(result['schema'], 'ascend-observation/1')
        self.assertFalse(result['model_ready'])
        self.assertEqual(result['coverage'], 'single_recorded_execution')
        self.assertEqual(result['events'][0]['args'], raw)
        self.assertEqual(result['events'][0]['source_index'], 1)
        self.assertNotIn('BufferId', result['events'][0])
        self.assertNotIn('dependencies', result)
        self.assertEqual(result['observed_flows'][0]['raw']['id'], 'f1')
        self.assertEqual(result['metadata'][0]['args']['name'], 'MTE2 raw')
        self.assertEqual(result['source']['sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(result['time_unit'], 'us')

    def test_nested_repeated_names_pair_by_thread_stack(self):
        result = self.load([
            {'ph':'B','name':'same','pid':1,'tid':1,'ts':1},
            {'ph':'B','name':'same','pid':1,'tid':1,'ts':2},
            {'ph':'B','name':'other','pid':1,'tid':2,'ts':3},
            {'ph':'E','pid':1,'tid':1,'ts':4},
            {'ph':'E','pid':1,'tid':2,'ts':5},
            {'ph':'E','pid':1,'tid':1,'ts':6},
        ])
        self.assertEqual([(e['source_index'],e['dur']) for e in result['events']],[(0,5),(1,2),(2,2)])
        self.assertEqual(result['events'][0]['source_end_index'],5)

    def test_unmatched_missing_and_unsupported_are_visible(self):
        result = self.load([
            {'ph':'E','pid':1,'tid':1,'ts':1},
            {'ph':'B','name':'open','pid':1,'tid':1,'ts':2},
            {'ph':'X','name':'missing'}, {'ph':'Q'}, 'bad',
        ])
        self.assertTrue({'unmatched_end','unmatched_begin','missing_fields','unsupported_phase','invalid_record'} <= self.codes(result))

    def test_duration_invalid_not_coerced(self):
        for dur in [-1,float('nan'),float('inf'),'3',None,True]:
            with self.subTest(dur=dur):
                result=self.load([{'ph':'X','name':'x','pid':0,'tid':0,'ts':0,'dur':dur}])
                self.assertEqual(result['events'],[])
                self.assertIn('invalid_number',self.codes(result))

    def test_timestamp_invalid_and_time_reversal(self):
        result=self.load([
            {'ph':'B','name':'x','pid':0,'tid':0,'ts':5},
            {'ph':'E','pid':0,'tid':0,'ts':3},
            {'ph':'X','name':'bad','pid':0,'tid':0,'ts':float('nan'),'dur':1},
        ])
        self.assertEqual(result['events'],[])
        self.assertIn('time_reversal',self.codes(result))
        self.assertIn('invalid_number',self.codes(result))

    def test_no_timestamp_sort_or_causality_inference(self):
        result=self.load([{'ph':'X','name':str(t),'pid':0,'tid':0,'ts':t,'dur':1} for t in [10,1]])
        self.assertEqual([e['ts'] for e in result['events']],[10,1])

    def test_csv_explicit_map_preserves_fields_and_line(self):
        self.path.write_text('Op,Clock,Length,Unmapped\nAdd,12.5,2,opaque\n',encoding='utf-8')
        result=import_trace(self.path,format='csv',columns={'name':'Op','ts':'Clock','dur':'Length'})
        event=result['events'][0]
        self.assertEqual((event['ts'],event['dur']),(12.5,2))
        self.assertEqual(event['source_line'],2)
        self.assertEqual(event['args']['Unmapped'],'opaque')
        self.assertIn('missing_optional_columns',self.codes(result))

    def test_csv_map_invalid_requires_explicit_schema(self):
        self.path.write_text('Op,Clock\nx,1\n',encoding='utf-8')
        for mapping in [None,{}, {'name':'Op'}, {'name':'Op','ts':'Absent'}, {'name':'Op','ts':'Clock','bogus':'Op'}, {'name':[], 'ts':'Clock'}]:
            with self.subTest(mapping=mapping):
                with self.assertRaises(ValueError):
                    import_trace(self.path,format='csv',columns=mapping)

    def test_csv_invalid_numeric_and_duplicate_headers(self):
        self.path.write_text('Op,Clock,Duration\nx,1,-3\nx,nan,1\n',encoding='utf-8')
        result=import_trace(self.path,format='csv',columns={'name':'Op','ts':'Clock','dur':'Duration'})
        self.assertEqual(result['events'],[])
        self.assertIn('invalid_number',self.codes(result))
        self.path.write_text('Op,Clock,Clock\nx,1,2\n',encoding='utf-8')
        with self.assertRaises(ValueError):
            import_trace(self.path,format='csv',columns={'name':'Op','ts':'Clock'})

    def test_official_aggregate_csv_is_not_a_trace_even_with_mapping(self):
        self.path.write_text('instr,addr,PIPE,call_count,cycles,running_time(us),detail\nADD,0x1,V,5,40,0.2,opaque\n',encoding='utf-8')
        for mapping in [None, {'name':'instr','ts':'running_time(us)'}]:
            result=import_trace(self.path,format='csv',columns=mapping)
            self.assertEqual(result['coverage'],'aggregated_instruction_statistics')
            self.assertEqual(result['events'],[])
            self.assertEqual(result['statistics'][0]['raw']['call_count'],'5')
            self.assertFalse(result['model_ready'])

    def test_cli_round_trip_and_input_protection(self):
        self.load([{'ph':'X','name':'x','pid':0,'tid':0,'ts':3,'dur':1}])
        output=Path(self.temp.name)/'observations.json'
        command=[sys.executable,'-m','tools.ascend_flow.trace_import','--input',str(self.path),'--output',str(output),'--time-unit','us']
        run=subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(json.loads(output.read_text(encoding='utf-8'))['time_unit'],'us')
        before=self.path.read_bytes()
        run=subprocess.run(command[:command.index('--output')]+['--output',str(self.path)],capture_output=True,text=True)
        self.assertEqual(run.returncode,2)
        self.assertEqual(self.path.read_bytes(),before)

    def test_metadata_cannot_override_source_locator(self):
        result=self.load([{'ph':'M','name':'thread_name','source_index':999,'args':{'name':'V'}}])
        self.assertEqual(result['metadata'][0]['source_index'],0)

    def test_nested_end_time_reversal_is_diagnosed(self):
        result=self.load([
            {'ph':'B','name':'outer','pid':0,'tid':0,'ts':1},
            {'ph':'B','name':'inner','pid':0,'tid':0,'ts':2},
            {'ph':'E','pid':0,'tid':0,'ts':10},
            {'ph':'E','pid':0,'tid':0,'ts':5},
        ])
        self.assertIn('time_reversal',self.codes(result))

    def test_complete_duration_never_certifies_capture_completion(self):
        result=self.load([{'ph':'X','name':'finished-looking','pid':0,'tid':0,'ts':1,'dur':500}])
        self.assertEqual(result['capture_status'],'unknown')
        self.assertFalse(result['model_ready'])

    def test_invalid_document_and_unknown_format(self):
        self.path.write_text('{}',encoding='utf-8')
        with self.assertRaises(ValueError): import_trace(self.path)
        with self.assertRaises(ValueError): import_trace(self.path,format='guess')


if __name__ == '__main__':
    unittest.main()
