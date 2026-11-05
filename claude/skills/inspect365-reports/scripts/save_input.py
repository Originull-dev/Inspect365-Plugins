"""Save one MCP tool response, exactly as returned, as a recipe input file.

Usage: python3 save_input.py <run-dir> <query-id> < response.json
Accepts the MCP envelope {"result": "<json text>"} or the inner JSON, and checks the echo:
aggregate responses must carry the query's maxBuckets, query responses its fields and maxResults, every
tenant-scoped response the run's tenant, and both exactly the query's filters with their values
(filter_problems). save_from_transcript.py calls save() directly; --verify rechecks a whole run.
"""
import json, re, sys, pathlib

HERE = pathlib.Path(__file__).resolve().parent


def spec_for(run, qid):
    recipe_dir = json.load(open(run / 'run.json'))['recipeDir']
    return {q['id']: q for q in json.load(open(HERE / 'recipes.json'))[recipe_dir]['queries']}[qid]


def unwrap(raw):
    """Return the inner response object from the MCP envelope or the inner JSON itself."""
    if isinstance(raw, str):
        raw = json.loads(raw)
    if isinstance(raw, dict) and isinstance(raw.get('result'), str):
        try:
            return json.loads(raw['result'])
        except json.JSONDecodeError:
            return {'text': raw['result']}
    return raw


# Filters the server adds on its own: the tenant scope, hiding findings still in the Detected window, and the record type
# of the two configuration entities, which share one container.
SERVER_FILTERS = ({'field': 'tenantId', 'operator': 'eq'}, {'field': 'latestStatusName', 'operator': 'ne', 'value': 'Detected'},
                  {'field': 'docType', 'operator': 'eq', 'value': 'endpointState'},
                  {'field': 'docType', 'operator': 'eq', 'value': 'configurationItem'})


def _fill(v, params):
    if isinstance(v, str):
        return re.sub(r'\{(\w+)\}', lambda m: str(params.get(m.group(1), m.group(0))), v)
    if isinstance(v, list):
        return [_fill(x, params) for x in v]
    return v


def _key(f):
    return (f.get('field'), f.get('operator'), json.dumps(f.get('value'), sort_keys=True), f.get('scope'))


def filter_problems(run, spec, inner):
    """Echoed filters must equal the query's filters exactly, values included, apart from SERVER_FILTERS.
    Catches a response that answered a different call (the dev server can cross responses)."""
    params = json.load(open(pathlib.Path(run) / 'run.json'))
    want = sorted(_key({**f, 'value': _fill(f.get('value'), params)}) for f in spec.get('filters', []))
    echo = inner.get('appliedFilters')
    if echo is None and isinstance(inner.get('window'), list):
        # finding-activity-summary echoes its date window instead, each date widened to the whole day
        echo = [{**w, 'value': str(w.get('value'))[:10]} for w in inner['window']]
    if echo is None and want:
        return ['the response echoes no filters']
    got = sorted(_key(a) for a in echo or []
                 if not any(all(a.get(k) == v for k, v in sf.items()) for sf in SERVER_FILTERS))
    problems = [f'missing filter {w[:3]}' for w in want if w not in got]
    problems += [f'extra filter {g[:3]}' for g in got if g not in want]
    return problems


def verify(run):
    """Check every saved input of a run against its query list, strictly. Returns a list of problems."""
    run = pathlib.Path(run)
    recipe_dir = json.load(open(run / 'run.json'))['recipeDir']
    out = []
    for q in json.load(open(HERE / 'recipes.json'))[recipe_dir]['queries']:
        path = run / 'inputs' / f"{q['id']}.json"
        if not path.exists():
            out.append(f"{q['id']}: no saved input")
            continue
        inner = json.load(open(path))
        if q['tool'] in ('query', 'aggregate'):
            out += [f"{q['id']}: {p}" for p in filter_problems(run, q, inner)]
            if q.get('groupBy') and inner.get('groupBy') != q['groupBy']:
                out.append(f"{q['id']}: groupBy {inner.get('groupBy')} != {q['groupBy']}")
            if q['tool'] == 'aggregate' and 'maxBuckets' in q and inner.get('maxBuckets') != q['maxBuckets']:
                out.append(f"{q['id']}: maxBuckets {inner.get('maxBuckets')} != {q['maxBuckets']}")
            if q['tool'] == 'query' and 'fields' in q and inner.get('selectedFields') not in (None, q['fields']):
                out.append(f"{q['id']}: fields differ")
    return out


def save(run, qid, inner):
    run = pathlib.Path(run)
    spec = spec_for(run, qid)
    if spec['tool'] == 'aggregate' and 'maxBuckets' in spec:
        assert inner.get('maxBuckets') == spec['maxBuckets'], f"echo mismatch: maxBuckets {inner.get('maxBuckets')} != {spec['maxBuckets']}"
    if spec.get('groupBy'):
        assert inner.get('groupBy') == spec['groupBy'], 'echo mismatch: groupBy'
    if spec['tool'] == 'query':
        if 'fields' in spec and inner.get('selectedFields') is not None:
            assert inner['selectedFields'] == spec['fields'], 'echo mismatch: fields'
        if 'maxResults' in spec and inner.get('maxResults') is not None:
            assert inner['maxResults'] == spec['maxResults'], f"echo mismatch: maxResults {inner.get('maxResults')} != {spec['maxResults']}"
    if spec['tool'] in ('query', 'aggregate'):
        problems = filter_problems(run, spec, inner)
        assert not problems, 'echo mismatch: ' + '; '.join(problems)
        tid = json.load(open(run / 'run.json'))['tenantId']
        echoed = inner.get('tenantId') or next((a['value'] for a in inner.get('appliedFilters', []) if a['field'] == 'tenantId'), None)
        assert echoed == tid, f'echo mismatch: tenant {echoed} != {tid}'
    (run / 'inputs').mkdir(exist_ok=True)
    (run / 'inputs' / f'{qid}.json').write_text(json.dumps(inner, indent=1, ensure_ascii=False))
    return len(json.dumps(inner))


if __name__ == '__main__':
    if sys.argv[1] == '--verify':  # python3 save_input.py --verify <run-dir> [...]
        bad = False
        for arg in sys.argv[2:]:
            problems = verify(arg)
            print(f'{pathlib.Path(arg).name}: ' + ('every saved input matches its query' if not problems else f'{len(problems)} problems'))
            for p in problems:
                print('  ', p)
            bad |= bool(problems)
        sys.exit(1 if bad else 0)
    run, qid = pathlib.Path(sys.argv[1]), sys.argv[2]
    print('saved', qid, save(run, qid, unwrap(sys.stdin.read())), 'chars')
