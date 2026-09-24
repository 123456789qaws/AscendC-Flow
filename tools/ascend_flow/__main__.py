"""Run from workspace root with python -m tools.ascend_flow."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys


def doctor():
    return {
        'schema': 'ascend-environment/1', 'platform': platform.platform(),
        'python': sys.version, 'hardware_executed': False,
        'tools': {name: shutil.which(name) for name in
                  ('msopprof', 'msprof', 'mssanitizer', 'ascendc', 'ccec', 'npu-smi')},
        'cann_environment': {name: os.environ.get(name) for name in
                             ('ASCEND_HOME_PATH', 'ASCEND_TOOLKIT_HOME')},
        'note': 'PATH discovery only; no device detection or version compatibility claim.',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Ascend research flow adapter (not a hardware simulator).')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('doctor', help='Read tool availability without executing tools')
    trace = commands.add_parser('import-trace', help='Preserve observed events; never infer full program semantics')
    trace.add_argument('input', type=Path)
    trace.add_argument('--output', type=Path, required=True)
    trace.add_argument('--format', choices=['chrome', 'csv'], default='chrome')
    trace.add_argument('--columns', type=Path, help='Explicit JSON column map for custom event CSV')
    trace.add_argument('--time-unit', default='unknown')
    trace.add_argument('--capture-manifest', type=Path, help='Hash-bound collection status and failure log evidence')
    for name in ['analyze', 'export-pnml']:
        command = commands.add_parser(name, help='Use an explicitly specified finite semantic program')
        command.add_argument('input', type=Path)
        command.add_argument('--output', type=Path, required=True)
        if name == 'analyze':
            command.add_argument('--state-limit', type=int, default=100000)
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            print(json.dumps(doctor(), ensure_ascii=True, indent=2))
            return 0
        if args.input.resolve() == args.output.resolve():
            raise ValueError('Output must not overwrite its input.')
        if args.command == 'import-trace':
            from .trace_import import import_trace
            columns = json.loads(args.columns.read_text(encoding='utf-8-sig')) if args.columns else None
            result = import_trace(args.input, format=args.format, columns=columns, time_unit=args.time_unit)
            result['capture_status'] = 'unknown'
            if args.capture_manifest:
                evidence_raw = args.capture_manifest.read_bytes()
                evidence = json.loads(evidence_raw.decode('utf-8-sig'))
                if (not isinstance(evidence, dict) or evidence.get('schema') != 'ascend-capture-evidence/1'
                    or result['source']['sha256'] not in
                    [entry.get('sha256') for entry in evidence.get('artifacts', []) if isinstance(entry, dict)]):
                    raise ValueError('Capture manifest must bind this exact input SHA-256.')
                status = evidence.get('application_completion')
                if status not in ('failed_or_partial', 'not_established_by_log_alone', 'sample_completion_markers_observed'):
                    raise ValueError('Unsupported capture status; success must not be inferred from exit 0.')
                result['capture_status'] = status
                result['capture_evidence'] = {'path': str(args.capture_manifest.resolve()),
                    'sha256': hashlib.sha256(evidence_raw).hexdigest(),
                    'required_sample_markers': evidence.get('required_sample_markers', []),
                    'observed_failure_lines': evidence.get('observed_failure_lines', [])}
            rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
        else:
            raw = args.input.read_bytes()
            spec = json.loads(raw.decode('utf-8-sig'))
            if not isinstance(spec, dict) or spec.get('schema') != 'ascend-program/1':
                raise ValueError('Requires ascend-program/1; a recorded trace is not a complete program.')
            from .model import analyze, compile_net, export_pnml
            if args.command == 'analyze':
                result = analyze(spec, state_limit=args.state_limit)
                result['input_source'] = {'path': str(args.input.resolve()),
                                          'sha256': hashlib.sha256(raw).hexdigest()}
                rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
            else:
                rendered = export_pnml(compile_net(spec))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + '\n', encoding='utf-8')
        print(json.dumps({'output': str(args.output.resolve()), 'command': args.command}, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f'Input/analysis error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
