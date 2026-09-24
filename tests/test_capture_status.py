import unittest
from tools.ascend_flow.collect_capture_artifacts import assess_log


class CaptureStatusTest(unittest.TestCase):
    def test_exit_zero_without_markers_is_not_success(self):
        self.assertEqual(assess_log('profiler exit 0', [])['application_completion'], 'not_established_by_log_alone')

    def test_fatal_failure_overrides_application_marker(self):
        result = assess_log('ADD_EXIT success=1\nChild process killed by signal 6', ['ADD_EXIT success=1'])
        self.assertEqual(result['application_completion'], 'failed_or_partial')

    def test_optional_tool_error_is_retained_with_sample_completion(self):
        result = assess_log('[ERROR] optional tool init failed\nCHECK_OK\nCLEANUP_OK', ['CHECK_OK','CLEANUP_OK'])
        self.assertEqual(result['application_completion'], 'sample_completion_markers_observed')
        self.assertEqual(len(result['observed_failure_lines']), 1)

    def test_missing_marker_does_not_promote_completion(self):
        result = assess_log('CHECK_OK', ['CHECK_OK','CLEANUP_OK'])
        self.assertEqual(result['application_completion'], 'not_established_by_log_alone')


if __name__ == '__main__':
    unittest.main()
