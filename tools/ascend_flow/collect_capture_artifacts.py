"""Copy selected generated evidence from this task's WSL capture, never source trees."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil


def assess_log(log, required_markers):
    fatal_words = ('killed by signal', 'double free', 'forcibly killed', 'Running task failed')
    failures = [line for line in log.splitlines()
                if '[ERROR]' in line or any(word in line for word in fatal_words)]
    fatal = any(any(word in line for word in fatal_words) for line in failures)
    markers = [{'text': marker, 'observed': marker in log} for marker in required_markers]
    if fatal:
        status = 'failed_or_partial'
    elif markers and all(item['observed'] for item in markers):
        status = 'sample_completion_markers_observed'
    else:
        status = 'not_established_by_log_alone'
    return {'observed_failure_lines': failures, 'application_completion': status,
            'required_sample_markers': markers}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('capture_root', type=Path)
    parser.add_argument('log', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--completion-marker', action='append', default=[],
                        help='Exact sample-specific verification/cleanup output, not a profiler success line')
    args = parser.parse_args()
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = []
    wanted = sorted(args.capture_root.glob('OPPROF_*/simulator/trace.json'))
    if not wanted:
        raise SystemExit('No simulator trace found')
    if len(wanted) != 1:
        raise SystemExit('Ambiguous captures: choose a directory containing exactly one OPPROF result')
    trace = wanted[0]
    files = [(trace, 'trace.json'), (args.log, 'capture.log')]
    for pattern in ('core0*/*instr_exe.csv', 'core0*/*code_exe.csv'):
        files += [(f, f.name) for f in sorted(trace.parent.glob(pattern))]
    for source, name in files:
        target = destination/name
        shutil.copyfile(source, target)
        artifacts.append({'source': str(source.resolve()), 'file': name,
                          'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                          'bytes': target.stat().st_size})
    log = args.log.read_text(encoding='utf-8', errors='replace')
    manifest = {'schema': 'ascend-capture-evidence/1', 'artifacts': artifacts,
                **assess_log(log, args.completion_marker),
                'hardware_execution': False,
                'warning': 'Profiler output or exit 0 does not prove application completion or deadlock freedom.'}
    (destination/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'files': len(files), 'trace_bytes': trace.stat().st_size,
                      'application_completion': manifest['application_completion']}, ensure_ascii=True))


if __name__ == '__main__':
    main()
