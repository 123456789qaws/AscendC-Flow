"""Import recorded observations, never infer resource identities or causality.

Chrome times retain their numeric values; unit is caller-declared (unknown by
 default). CSV event tables require a canonical-field -> header mapping.
"""
import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path


def _diagnostic(result, code, message, index=None):
    item = {'code': code, 'message': message}
    if index is not None:
        item['source_index'] = index
    result['diagnostics'].append(item)


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _valid_numbers(record, result, index, duration=False):
    if not _number(record.get('ts')):
        _diagnostic(result, 'invalid_number', 'Timestamp must be a finite number.', index)
        return False
    if duration and (not _number(record.get('dur')) or record['dur'] < 0):
        _diagnostic(result, 'invalid_number', 'Duration must be finite and nonnegative.', index)
        return False
    return True


def _event(record, index, duration):
    return {'id': f'observation-{index}', 'name': record['name'],
            'pid': record.get('pid'), 'tid': record.get('tid'),
            'ts': record['ts'], 'dur': duration, 'args': record.get('args', {}),
            'source_index': index}


def _chrome(document, result):
    records = document.get('traceEvents') if isinstance(document, dict) else document
    if not isinstance(records, list):
        raise ValueError('Chrome input must be a list or an object containing traceEvents list.')
    stacks = {}
    last_stack_time = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            _diagnostic(result, 'invalid_record', 'Expected an event object.', index)
            continue
        phase = record.get('ph')
        if phase == 'M':
            result['metadata'].append({**record, 'source_index': index})
            if record.get('name') not in ('thread_name', 'process_name'):
                _diagnostic(result, 'uninterpreted_metadata', 'Metadata preserved without interpretation.', index)
            continue
        if phase not in ('X', 'B', 'E', 's', 't', 'f'):
            _diagnostic(result, 'unsupported_phase', f'Unsupported phase {phase!r}; no event inferred.', index)
            continue
        required = ['ts', 'pid', 'tid']
        if phase in ('X', 'B'):
            required.append('name')
        if phase == 'X':
            required.append('dur')
        missing = [field for field in required if field not in record]
        if missing:
            _diagnostic(result, 'missing_fields', 'Missing fields: ' + ', '.join(missing), index)
            continue
        if not _valid_numbers(record, result, index, phase == 'X'):
            continue
        if any(not isinstance(record[key], (str, int)) or isinstance(record[key], bool) for key in ('pid', 'tid')):
            _diagnostic(result, 'invalid_record', 'pid/tid must be string or integer identities.', index)
            continue
        if phase in ('X', 'B') and not isinstance(record['name'], str):
            _diagnostic(result, 'invalid_record', 'Event name must be a string.', index)
            continue
        key = (record['pid'], record['tid'])
        if phase in ('B', 'E'):
            if key in last_stack_time and record['ts'] < last_stack_time[key]:
                _diagnostic(result, 'time_reversal', 'B/E records are not chronological within this thread; input order was retained.', index)
            last_stack_time[key] = record['ts']
        if phase == 'X':
            result['events'].append(_event(record, index, record['dur']))
        elif phase == 'B':
            stack = stacks.setdefault(key, [])
            if stack and record['ts'] < stack[-1][1]['ts']:
                _diagnostic(result, 'time_reversal', 'Nested begin precedes its open parent.', index)
            stack.append((index, record))
        elif phase == 'E':
            stack = stacks.setdefault(key, [])
            if not stack:
                _diagnostic(result, 'unmatched_end', 'No begin for this pid/tid.', index)
                continue
            start_index, start = stack.pop()
            duration = record['ts'] - start['ts']
            if duration < 0 or not math.isfinite(duration):
                _diagnostic(result, 'time_reversal', 'End precedes begin or interval overflows.', index)
                continue
            event = _event(start, start_index, duration)
            event['source_end_index'] = index
            event['end_args'] = record.get('args', {})
            result['events'].append(event)
        else:
            result['observed_flows'].append({'source_index': index, 'raw': record})
            if 'id' not in record and 'id2' not in record:
                _diagnostic(result, 'missing_fields', 'Observed flow lacks id/id2; retained without pairing.', index)
    for stack in stacks.values():
        for index, _ in stack:
            _diagnostic(result, 'unmatched_begin', 'No matching end in recorded input.', index)
    # Restore input positions for paired spans; timestamp order is not causality.
    result['events'].sort(key=lambda event: event['source_index'])


def _csv(text, result, columns):
    reader = csv.DictReader(io.StringIO(text, newline=''))
    headers = reader.fieldnames
    if not headers or len(set(headers)) != len(headers):
        raise ValueError('CSV requires nonempty, unique headers.')
    aggregate = {'instr', 'addr', 'pipe', 'call_count', 'cycles', 'running_time(us)', 'detail'}
    if aggregate <= {header.strip().lower() for header in headers}:
        result['coverage'] = 'aggregated_instruction_statistics'
        result['statistics'] = []
        for index, row in enumerate(reader):
            result['statistics'].append({'source_index': index, 'source_line': reader.line_num, 'raw': row})
        _diagnostic(result, 'aggregated_statistics', 'Instruction aggregates cannot recover per-execution order or timestamps; running_time is not a timestamp.')
        return
    allowed = {'name', 'ts', 'dur', 'pid', 'tid'}
    if (not isinstance(columns, dict) or not {'name', 'ts'} <= columns.keys()
            or not columns.keys() <= allowed
            or any(not isinstance(header, str) or header not in headers for header in columns.values())
            or len(set(columns.values())) != len(columns)):
        raise ValueError('CSV requires explicit unique field-to-header mapping: name/ts required; dur/pid/tid optional.')
    optional = sorted(allowed - columns.keys())
    if optional:
        _diagnostic(result, 'missing_optional_columns', 'Unmapped optional fields: ' + ', '.join(optional))
    result['input_kind'] = 'user_mapped_event_table'
    for index, row in enumerate(reader):
        line = reader.line_num
        if None in row or any(value is None for value in row.values()):
            _diagnostic(result, 'invalid_record', f'CSV row at line {line} has a different width than its header.', index)
            continue
        record = {field: row[header] for field, header in columns.items()}
        if not record['name']:
            _diagnostic(result, 'missing_fields', f'Empty name at CSV line {line}.', index)
            continue
        try:
            record['ts'] = float(record['ts'])
            if 'dur' in record:
                record['dur'] = float(record['dur'])
        except ValueError:
            _diagnostic(result, 'invalid_number', f'Invalid numeric field at CSV line {line}.', index)
            continue
        if not _valid_numbers(record, result, index, 'dur' in record):
            continue
        record['args'] = row
        event = _event(record, index, record.get('dur'))
        event['source_line'] = line
        result['events'].append(event)


def import_trace(path, format='chrome', columns=None, time_unit='unknown'):
    """Return observations and diagnostics; invalid document/schema raises ValueError."""
    if format not in ('chrome', 'csv'):
        raise ValueError('Supported formats are chrome and csv.')
    if not isinstance(time_unit, str) or not time_unit.strip():
        raise ValueError('time_unit must be an explicit label or unknown.')
    path = Path(path)
    raw = path.read_bytes()
    result = {'schema': 'ascend-observation/1',
              'source': {'path': str(path.resolve()), 'sha256': hashlib.sha256(raw).hexdigest()},
              'events': [], 'metadata': [], 'observed_flows': [], 'diagnostics': [],
              'time_unit': time_unit, 'coverage': 'single_recorded_execution',
              'capture_status': 'unknown', 'model_ready': False}
    text = raw.decode('utf-8-sig')
    if format == 'chrome':
        _chrome(json.loads(text), result)
    else:
        _csv(text, result, columns)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--format', choices=('chrome', 'csv'), default='chrome')
    parser.add_argument('--columns', help='JSON file mapping canonical fields to CSV headers')
    parser.add_argument('--time-unit', default='unknown')
    args = parser.parse_args(argv)
    try:
        if Path(args.input).resolve() == Path(args.output).resolve():
            raise ValueError('Output must not overwrite the input trace.')
        columns = json.loads(Path(args.columns).read_text(encoding='utf-8-sig')) if args.columns else None
        result = import_trace(args.input, args.format, columns, args.time_unit)
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    except (OSError, ValueError) as error:
        parser.exit(2, f'trace import failed: {error}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
