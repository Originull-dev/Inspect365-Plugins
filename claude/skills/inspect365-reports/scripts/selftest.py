"""Test this package where it runs, in Copilot Cowork, Claude or ChatGPT, before trusting its reports.

    python3 selftest.py offline --out <folder>
    python3 selftest.py plan --tenant-id <id> --tenant-name "<name>" --out <folder>
    python3 selftest.py check <run-folder>

offline makes no tool calls. It checks that this Python compiles every script, that every file is the one the build
packaged (package.json holds each file's SHA-256), the run folder rules (the skill folder is refused, --out is
writable, a second plan starts a new folder), that every report plans its calls with the argument types the
Inspect 365 servers take, and that save refuses a result echoing another call or tenant. plan prints three live
calls: open findings by type twice and one page of enabled users. check tests what was saved from them: the
echoes save checks, row counts against the counts each result states, the two copies of one call matching
exactly, and a second page continuing the first. Each check prints PASS or FAIL, and the exit code is 1 if any
fails. Standard library only, and Python 3.8 syntax, so an older sandbox still gets as far as reporting its version.
"""
import copy, hashlib, json, pathlib, platform, shutil, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
SKILL = HERE.parent
sys.path.insert(0, str(HERE))
PLATFORM_FILES = {'.companion-manifest.json'}  # Cowork adds it to an installed skill (seen 2026-10-19)
TEST_TENANT = '00000000-0000-0000-0000-000000000000'
OTHER_TENANT = '11111111-1111-1111-1111-111111111111'
# The argument types the Inspect 365 servers take. filters is a string holding a JSON array of filter objects.
TYPES = {'tenantId': str, 'entity': str, 'groupBy': str, 'findingId': str, 'pageToken': str,
         'maxBuckets': int, 'maxResults': int, 'detail': bool}
PASSED = []


def result(name, problems, detail=''):
    PASSED.append(not problems)
    if problems:
        more = f' (and {len(problems) - 6} more)' if len(problems) > 6 else ''
        print(f'FAIL {name}: ' + '; '.join(problems[:6]) + more)
    else:
        print(f'PASS {name}' + (f': {detail}' if detail else ''))


def finish(label):
    print(f'{label}: {sum(PASSED)} of {len(PASSED)} checks passed')
    sys.exit(0 if all(PASSED) else 1)


def run_script(*args):
    return subprocess.run([sys.executable, '-B'] + [str(a) for a in args], capture_output=True, text=True)


def run_folder(stdout):
    first = stdout.splitlines()[0] if stdout else ''
    return pathlib.Path(first[len('run folder: '):]) if first.startswith('run folder: ') else None


def argument_problems(args):
    out = []
    for k, v in args.items():
        if k == 'filters':
            try:
                parsed = json.loads(v) if isinstance(v, str) else None
            except ValueError:
                parsed = None
            if not (isinstance(parsed, list) and all(isinstance(f, dict) and 'field' in f and 'operator' in f for f in parsed)):
                out.append('filters is not a string holding a JSON array of filters')
        elif k == 'fields':
            if not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
                out.append('fields is not a list of strings')
        elif k in TYPES:
            if type(v) is not TYPES[k]:
                out.append(f'{k} is {type(v).__name__}, not {TYPES[k].__name__}')
        else:
            out.append(f'unexpected argument {k}')
    return out


def check_python():
    problems = []
    for p in sorted(HERE.glob('*.py')):
        try:
            compile(p.read_text(encoding='utf-8'), str(p), 'exec')
        except SyntaxError as e:
            problems.append(f'{p.name} line {e.lineno}: {e.msg}')
    result('python', problems, f'Python {platform.python_version()} compiles every script')
    return not problems


def check_package():
    try:
        pkg = json.loads((HERE / 'package.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        result('package', [f"package.json can't be read ({e})"])
        return
    problems = []
    for rel, digest in pkg['files'].items():
        p = SKILL / rel
        if not p.is_file():
            problems.append(f'{rel} is missing')
        elif hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            problems.append(f'{rel} differs from the build')
    result('package', problems, f"{pkg['version']} ({pkg['environment']}), all {len(pkg['files'])} files as built")
    listed = {(SKILL / rel).resolve() for rel in pkg['files']} | {(HERE / 'package.json').resolve()}
    extra = [str(p.relative_to(SKILL)) for p in sorted(SKILL.rglob('*'))
             if p.is_file() and p.resolve() not in listed and '__pycache__' not in p.parts and p.name not in PLATFORM_FILES]
    if extra:
        print('NOTE files the build did not add: ' + ', '.join(extra[:10]))


def plan_args(recipe, out):
    script = [HERE / 'selftest.py', 'plan'] if recipe == 'selftest' else [HERE / 'report.py', 'plan', recipe]
    return script + ['--tenant-id', TEST_TENANT, '--tenant-name', 'Self test', '--out', out]


def cmd_offline(opt):
    out = pathlib.Path(opt.get('--out', '.')).resolve()
    if not check_python():
        finish('offline')
    check_package()
    import report, save_input  # after the compile check, so a too-old Python still reports its version

    problems, tmp = [], None
    r = run_script(*plan_args('tenant-overview', SKILL))
    if r.returncode == 0 or 'skill folder' not in r.stdout + r.stderr:
        problems.append('a run folder in the skill folder was not refused')
    try:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix='inspect365-selftest-', dir=str(out)))
    except OSError as e:
        problems.append(f"can't write in {out} ({e.strerror}); pass --out with a folder you can write to")
    if tmp:
        names = []
        for _ in range(2):
            r = run_script(*plan_args('tenant-overview', tmp))
            if r.returncode or not run_folder(r.stdout):
                problems.append('plan failed: ' + (r.stdout + r.stderr).strip()[-200:])
                break
            names.append(run_folder(r.stdout))
        if len(names) == 2 and names[0] == names[1]:
            problems.append('a second plan reused the first run folder')
    result('run folders', problems, f'the skill folder is refused, {out} is writable, each plan starts a new folder')
    if not tmp:
        finish('offline')

    problems, count, selftest_run = [], 0, None
    for recipe in list(report.RECIPES) + ['selftest']:
        r = run_script(*plan_args(recipe, tmp))
        run_dir = run_folder(r.stdout)
        if r.returncode or not run_dir:
            problems.append(f'{recipe}: plan failed: ' + (r.stdout + r.stderr).strip()[-200:])
            continue
        selftest_run = run_dir if recipe == 'selftest' else selftest_run
        for c in json.loads((run_dir / 'calls.json').read_text(encoding='utf-8')):
            count += 1
            problems += [f"{recipe} {c['id']}: {p}" for p in argument_problems(c['arguments'])]
    result('call arguments', problems, f'{count} planned calls across {len(report.RECIPES)} reports and this test '
           'use the argument types the servers take')

    problems = []
    if selftest_run:
        call = next(c for c in json.loads((selftest_run / 'calls.json').read_text()) if c['id'] == 'open_findings_by_type')
        spec = next(q for q in report.queries('selftest')['queries'] if q['id'] == 'open_findings_by_type')
        good = {'groupBy': spec['groupBy'], 'maxBuckets': spec['maxBuckets'], 'totalCount': 0, 'bucketCount': 0, 'results': [],
                'appliedFilters': [{'field': 'tenantId', 'operator': 'eq', 'value': TEST_TENANT}] + json.loads(call['arguments']['filters'])}
        other_filters, other_tenant = copy.deepcopy(good), copy.deepcopy(good)
        other_filters['appliedFilters'][1]['value'] = ['Needs Review']
        other_tenant['appliedFilters'][0]['value'] = OTHER_TENANT
        for name, inner, should_save in (('a matching result', good, True), ('a result with other filters', other_filters, False),
                                         ("another tenant's result", other_tenant, False)):
            try:
                save_input.save(selftest_run, 'open_findings_by_type', inner)
                if not should_save:
                    problems.append(f'{name} was saved')
            except AssertionError as e:
                if should_save:
                    problems.append(f'{name} was refused ({e})')
    else:
        problems.append("the self-test couldn't plan its calls")
    result('save checks', problems, "a matching result is saved; other filters and another tenant's result are refused")
    shutil.rmtree(tmp, ignore_errors=True)
    finish('offline')


def cmd_plan(a):
    import report
    run_dir, calls = report.new_run('selftest', 'selftest', dict(zip(a[0::2], a[1::2])))
    print(f'run folder: {run_dir}')
    print(f'{len(calls)} calls. Make each exactly as printed and write its result, exactly as returned, to raw/<call ID>.json. '
          'If enabled_users_page returns a nextPageToken, call it once more with the same arguments plus pageToken set to '
          'that value and write the result to raw/enabled_users_page.2.json; fetch no further pages. '
          f'Then run: selftest.py check "{run_dir}"')
    report.print_calls(calls)


def counts(qid, inner):
    rows = inner.get('results')
    if not isinstance(rows, list):
        return [f'{qid} has no list of results']
    stated = inner.get('resultCount', inner.get('bucketCount'))
    return [] if stated in (None, len(rows)) else [f'{qid} holds {len(rows)} rows but states {stated}']


def cmd_check(a):
    import report, save_input
    run_dir = pathlib.Path(a[0]).resolve()
    if json.load(open(run_dir / 'run.json')).get('recipeDir') != 'selftest':
        sys.exit(f'{run_dir} is not a self-test run folder')
    calls = {c['id']: c for c in json.load(open(run_dir / 'calls.json'))}
    got, problems = {}, []
    for qid in calls:
        path = run_dir / 'raw' / f'{qid}.json'
        if not path.exists():
            problems.append(f'{qid}: no saved result')
            continue
        inner = report.read_result(path.read_text(encoding='utf-8'))
        if isinstance(inner, dict):
            got[qid] = inner
        else:
            problems.append(f'{qid}: not the JSON the tool returns: {str(inner)[:150]}')
    result('saved results', problems, f'{len(got)} of {len(calls)} calls saved as JSON')

    problems = []
    for qid, inner in got.items():
        if calls[qid]['tool'] in ('query', 'aggregate'):
            try:
                save_input.save(run_dir, qid, inner)
            except AssertionError as e:
                problems.append(f'{qid}: {e}')
    result('echoes', problems, 'each result echoes the tenant, filters, grouping, fields and page size of its call')

    problems = [p for qid, inner in got.items() if calls[qid]['tool'] in ('query', 'aggregate') for p in counts(qid, inner)]
    result('row counts', problems, 'each result holds as many rows as it states')

    a1, a2 = got.get('open_findings_by_type'), got.get('open_findings_by_type_again')
    if a1 is None or a2 is None:
        problems = ['a result of the repeated call is missing']
    else:
        diff = sorted(k for k in set(a1) | set(a2) if a1.get(k) != a2.get(k))
        problems = [f"the two results of the same call differ in {', '.join(diff)}; a copy changed or the data did"] if diff else []
    result('copies', problems, 'two results of the same call match exactly')

    p1, problems, detail = got.get('enabled_users_page'), [], ''
    if p1 is None:
        problems.append('page 1 is missing')
    elif p1.get('nextPageToken'):
        path = run_dir / 'raw' / 'enabled_users_page.2.json'
        p2 = report.read_result(path.read_text(encoding='utf-8')) if path.exists() else None
        if not isinstance(p2, dict):
            problems.append('page 1 has a nextPageToken but page 2 was not saved as JSON')
        else:
            try:
                save_input.save(run_dir, 'enabled_users_page', p2)
            except AssertionError as e:
                problems.append(f'page 2: {e}')
            problems += counts('page 2', p2)
            ids1 = [r.get('id') for r in p1.get('results', [])]
            ids2 = [r.get('id') for r in p2.get('results', [])]
            if not ids2:
                problems.append('page 2 is empty')
            if set(ids1) & set(ids2):
                problems.append('page 2 repeats records from page 1')
            if len(ids1) != calls['enabled_users_page']['arguments']['maxResults']:
                problems.append('page 1 is not a full page')
            if p1.get('totalCount') != p2.get('totalCount'):
                problems.append('the two pages state different totals')
            detail = f"page 2 continues page 1 with no overlap ({p1.get('totalCount')} enabled users in all)"
    else:
        detail = f"one page held all {len(p1.get('results', []))} enabled users, so paging wasn't exercised"
    result('paging', problems, detail)
    finish('live')


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ('offline', 'plan', 'check'):
        sys.exit(__doc__)
    if sys.argv[1] == 'offline':
        cmd_offline(dict(zip(sys.argv[2::2], sys.argv[3::2])))
    elif sys.argv[1] == 'plan':
        cmd_plan(sys.argv[2:])
    else:
        cmd_check(sys.argv[2:])
