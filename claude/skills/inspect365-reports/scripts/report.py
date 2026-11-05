"""Run an Inspect 365 report recipe from a plugin skill (Copilot Cowork, Claude or ChatGPT).

    python3 report.py recipes
    python3 report.py plan <recipe> --tenant-id <id> --tenant-name "<name>" --out <folder> [--as-of YYYY-MM-DD]
    python3 report.py save <run-folder> <call-id> [<file> | -]
    python3 report.py status <run-folder>
    python3 report.py build <run-folder>

plan writes run.json and calls.json and prints each call. save reads the tool result the model wrote to
<run-folder>/raw/<call-id>.json (or the named file, or stdin for "-"). A result with a nextPageToken is page 1
of a longer list: the later pages go to raw/<call-id>.2.json, .3.json and so on, and save joins them once the
last page (no nextPageToken) is in, checking every page's echo. It then checks the echoed tenant, groupBy,
maxBuckets, fields and filters through save_input.py and stores the result in inputs/. build runs the recipe's
build script, renders report.html with render_report.py (no vendor branding; the run folder's brand.json, if
present, adds the user's own), and runs check_facts.py. The recipe scripts, the merged query lists
(recipes.json), renderer and template are copies of the report recipes made by
the plugin build. Standard library only: the host's script sandbox may have no network and
no package installs.
"""
import datetime as dt, json, pathlib, re, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from save_input import filter_problems, save, unwrap  # noqa: E402
from render_report import BrandError, render  # noqa: E402

PLUGIN_VERSION = '0.6.3'  # build.py writes the manifest's version
ENVIRONMENT = 'us-production'  # build.py writes "us-production" or "dev"
if ENVIRONMENT.startswith('__'):
    ENVIRONMENT = 'dev'
RECIPES = {'tenant-overview': 'tenant_overview', 'users-and-groups': 'identity_deep_dive', 'devices': 'devices_deep_dive',
           'entra-apps': 'entra_apps_deep_dive', 'installed-software': 'installed_software_deep_dive',
           'mailboxes-teams-sharepoint': 'collaboration_deep_dive', 'app-access': 'app_access'}
WINDOW_DAYS = 90  # windowStart = asOf minus 90 days, as in the repo's runs
DEF_LINE = re.compile(r'^- (?P<name>.*) \(id=(?P<id>[0-9a-fA-F-]{36}), orderId=(?P<order>-?\d+)\)(?:: (?P<desc>.*))?$')


def fill(v, params):
    if isinstance(v, str):
        return re.sub(r'\{(\w+)\}', lambda m: str(params.get(m.group(1), m.group(0))), v)
    if isinstance(v, list):
        return [fill(x, params) for x in v]
    if isinstance(v, dict):
        return {k: fill(x, params) for k, x in v.items()}
    return v


def call_args(q, run):
    args = {'tenantId': run['tenantId']} if q['tool'] in ('query', 'aggregate') else {}
    for k in ('entity', 'groupBy', 'maxBuckets', 'maxResults', 'fields', 'detail', 'findingId'):
        if k in q:
            args[k] = fill(q[k], run)
    if 'filters' in q:  # the servers take filters as a string holding a JSON array, not as the array
        args['filters'] = json.dumps(fill(q['filters'], run), ensure_ascii=False)
    return args


def queries(recipe_dir):
    return json.load(open(HERE / 'recipes.json'))[recipe_dir]


def slug(name):
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'tenant'


def definitions_from_text(text):
    """Turn a plain-text definition list (production before 2026-10-16) into the JSON shape the recipes read."""
    head = re.match(r'Finding definitions \((\d+), knowledgeVersion=([^)]*)\):', text)
    if not head:
        sys.exit('definitions: the result is neither JSON nor the plain-text definition list')
    defs, kind = [], None
    for line in text.splitlines():
        line = line.rstrip()
        m = DEF_LINE.match(line)
        if m:
            defs.append({'id': m['id'], 'type': kind, 'displayName': m['name'], 'description': m['desc'] or '',
                         'orderId': int(m['order'])})
        elif line.endswith(':') and not line.startswith('Finding definitions') and line:
            kind = line[:-1]
    if len(defs) != int(head.group(1)):
        sys.exit(f'definitions: parsed {len(defs)} of {head.group(1)} lines; save the result again exactly as returned')
    return {'knowledgeVersion': head.group(2), 'count': len(defs), 'definitions': defs, 'source': 'plain-text list'}


def new_run(recipe, recipe_dir, opt):
    """Create a new run folder in --out with run.json and calls.json; return the folder and the calls."""
    if '--tenant-id' not in opt or '--tenant-name' not in opt:
        sys.exit('plan needs --tenant-id and --tenant-name')
    as_of = dt.date.fromisoformat(opt.get('--as-of') or dt.datetime.now(dt.timezone.utc).date().isoformat())
    run = {'recipeDir': recipe_dir, 'recipe': recipe, 'tenantId': opt['--tenant-id'], 'tenantName': opt['--tenant-name'],
           'tenantSlug': slug(opt['--tenant-name']), 'asOf': as_of.isoformat(),
           'windowStart': (as_of - dt.timedelta(days=WINDOW_DAYS)).isoformat(), 'environment': ENVIRONMENT,
           'plugin': f'inspect365 {PLUGIN_VERSION}'}
    out = pathlib.Path(opt.get('--out', '.')).resolve()
    if out == HERE.parent or HERE.parent in out.parents:
        sys.exit(f'{out} is in the skill folder, which can be read-only and is replaced on update. '
                 'Pass --out with a folder you can write to, such as your working folder.')
    base = out / f'inspect365-{recipe}-{run["tenantSlug"]}-{run["asOf"]}'
    try:
        run_dir, n = base, 1
        while run_dir.exists() and any(run_dir.iterdir()):  # a new folder, so an earlier run's results never mix in
            n += 1
            run_dir = base.with_name(f'{base.name}-{n}')
        (run_dir / 'raw').mkdir(parents=True, exist_ok=True)
    except OSError as e:
        sys.exit(f"Can't create the run folder in {out} ({e.strerror}). Pass --out with a folder you can write to.")
    (run_dir / 'inputs').mkdir(exist_ok=True)
    json.dump(run, open(run_dir / 'run.json', 'w'), indent=1)
    calls = [{'id': q['id'], 'tool': q['tool'], 'arguments': call_args(q, run)} for q in queries(run['recipeDir'])['queries']]
    json.dump(calls, open(run_dir / 'calls.json', 'w'), indent=1)
    return run_dir, calls


def print_calls(calls):
    for c in calls:
        print(f"{c['id']} | {c['tool']} | {json.dumps(c['arguments'], ensure_ascii=False)}")


def cmd_plan(a):
    recipe = a[0]
    if recipe not in RECIPES:
        sys.exit(f'unknown recipe {recipe}; choose one of {", ".join(RECIPES)}')
    run_dir, calls = new_run(recipe, RECIPES[recipe], dict(zip(a[1::2], a[2::2])))
    print(f'run folder: {run_dir}')
    print(f'{len(calls)} calls. Save each result to raw/<call ID>.json, then run: report.py save "{run_dir}" <call ID>')
    print_calls(calls)


def read_result(text):
    try:
        return unwrap(text.strip())
    except json.JSONDecodeError:
        return text.strip()  # a plain-text definition list


def join_pages(run_dir, qid, spec, first):
    """Page 1 plus raw/<qid>.2.json, .3.json ... joined in order; None while a page is still to fetch."""
    pages, n = [first], 1
    while isinstance(pages[-1], dict) and pages[-1].get('nextPageToken'):
        n += 1
        path = run_dir / 'raw' / f'{qid}.{n}.json'
        if not path.exists():
            print(f"{qid}: page {n - 1} saved; the list continues. Call {spec['tool']} again with the same arguments plus "
                  f"pageToken set to the nextPageToken in the last page, exactly as returned, write the result to "
                  f"raw/{qid}.{n}.json, then run save again.")
            return None
        page = read_result(path.read_text(encoding='utf-8'))
        if not isinstance(page, dict):
            sys.exit(f'{qid}: page {n} is not the JSON the tool returns; save it again exactly as returned')
        problems = filter_problems(run_dir, spec, page) if spec['tool'] in ('query', 'aggregate') else []
        if problems:
            sys.exit(f'{qid}: page {n} answered a different call ({"; ".join(problems)}). Fetch it again with the same arguments.')
        pages.append(page)
    if n == 1:
        return first
    inner = dict(pages[0])
    inner.pop('nextPageToken', None)
    for page in pages[1:]:
        for rows, count in (('results', 'resultCount'), ('snapshots', 'snapshotCount')):
            if rows in page:
                inner[rows] = inner.get(rows, []) + page[rows]
                inner[count] = inner.get(count, 0) + page.get(count, len(page[rows]))
    inner['pagesJoined'] = n
    return inner


def cmd_save(a):
    run_dir, qid = pathlib.Path(a[0]).resolve(), a[1]
    src = a[2] if len(a) > 2 else str(run_dir / 'raw' / f'{qid}.json')
    raw = sys.stdin.read() if src == '-' else pathlib.Path(src).read_text(encoding='utf-8')
    spec = {q['id']: q for q in queries(json.load(open(run_dir / 'run.json'))['recipeDir'])['queries']}
    if qid not in spec:
        sys.exit(f'{qid} is not a call in this run')
    inner = read_result(raw)
    if isinstance(inner, dict) and inner.get('nextPageToken'):
        inner = join_pages(run_dir, qid, spec[qid], inner)
        if inner is None:
            return
    if spec[qid]['tool'] == 'list_finding_definitions':
        if isinstance(inner, str):
            inner = definitions_from_text(inner)
        elif isinstance(inner, dict) and 'definitions' not in inner and 'text' in inner:
            inner = definitions_from_text(inner['text'])
    if not isinstance(inner, dict):
        sys.exit(f'{qid}: the saved result is not the JSON the tool returns; save it again exactly as returned')
    try:
        print('saved', qid, save(run_dir, qid, inner), 'chars')
    except AssertionError as e:
        sys.exit(f'{qid}: {e}. The call did not match the plan; run it again exactly as printed and save it again.')


def missing(run_dir):
    run = json.load(open(run_dir / 'run.json'))
    return [q['id'] for q in queries(run['recipeDir'])['queries'] if not (run_dir / 'inputs' / f"{q['id']}.json").exists()]


def cmd_status(a):
    run_dir = pathlib.Path(a[0]).resolve()
    left = missing(run_dir)
    print('all calls saved' if not left else f'{len(left)} calls still to save: ' + ', '.join(left))


def cmd_build(a):
    run_dir = pathlib.Path(a[0]).resolve()
    left = missing(run_dir)
    if left:
        sys.exit(f'{len(left)} calls still to save: ' + ', '.join(left))
    run = json.load(open(run_dir / 'run.json'))
    if run['recipeDir'] == 'selftest':
        sys.exit('This is a self-test run folder; check it with selftest.py check.')
    (run_dir / 'report.html').unlink(missing_ok=True)  # a failed build must not leave an older report behind
    b = subprocess.run([sys.executable, str(HERE / f"{run['recipeDir']}_build.py"), str(run_dir)], capture_output=True, text=True)
    if b.returncode:
        text = (b.stdout + b.stderr).strip()
        if 'Traceback (most recent call last)' in text:
            text += ("\nThe build hit an error in this skill's scripts, not in the tenant's data. Tell the user the line above; "
                     "don't edit the scripts or the saved results.")
        sys.exit(text)
    try:
        render(run_dir)
    except BrandError as e:
        sys.exit(f'brand.json: {e}')
    c = subprocess.run([sys.executable, str(HERE / 'check_facts.py'), str(run_dir)], capture_output=True, text=True)
    print(b.stdout.strip())
    print(c.stdout.strip())
    if c.returncode:
        sys.exit('fact check failed; report.html is not valid')
    print(f'report: {run_dir / "report.html"}')


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ('recipes', 'plan', 'save', 'status', 'build'):
        sys.exit(__doc__)
    if sys.argv[1] == 'recipes':
        for r, d in RECIPES.items():
            print(r, queries(d).get('version'))
    else:
        {'plan': cmd_plan, 'save': cmd_save, 'status': cmd_status, 'build': cmd_build}[sys.argv[1]](sys.argv[2:])
