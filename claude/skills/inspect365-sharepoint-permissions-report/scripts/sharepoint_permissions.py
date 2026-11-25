"""Run the SharePoint permissions report from a plugin skill (Copilot Cowork, Claude or ChatGPT).

    python3 sharepoint_permissions.py plan --tenant-id <id> --tenant-name "<name>" --style report|explorer|both
                                           --audience msp|client --out <folder>
    python3 sharepoint_permissions.py save <run-folder> <call-id> [<file> | -]
    python3 sharepoint_permissions.py status <run-folder>
    python3 sharepoint_permissions.py build <run-folder>

plan writes run.json and calls.json and prints each call. save reads the tool result the model wrote to
<run-folder>/raw/<call-id>.json (or the named file, or stdin for "-"). A result with a nextPageToken is page 1
of a longer list: the later pages go to raw/<call-id>.2.json, .3.json and so on, and save joins them once the
last page (no nextPageToken) is in, checking every page's echo. It then checks the echoed tenant, fields,
maxResults and filters through save_input.py and stores the result in inputs/. A call marked firstPageOnly
(the latest collection run) keeps its first page and is never continued. build runs the recipe's build script,
which checks that every list is complete and writes the style the user picked: report.html (the flat report),
explorer.html (the Explorer) or both. The recipe script, the model,
the Explorer and its template, and the query list (recipes.json) are copies of the report recipe made by the
plugin build. Standard library only: the host's script sandbox may have no network and no package installs.
"""
import datetime as dt, json, pathlib, re, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from save_input import filter_problems, save, unwrap  # noqa: E402

PLUGIN_VERSION = '0.8.6'  # build.py writes the manifest's version
ENVIRONMENT = 'us-production'  # build.py writes "us-production" or "dev"
if ENVIRONMENT.startswith('__'):
    ENVIRONMENT = 'dev'
RECIPE, RECIPE_DIR = 'sharepoint-permissions', 'sharepoint_permissions'
AUDIENCES = ('msp', 'client')
STYLES = {'report': 'the flat report (report.html)', 'explorer': 'the Explorer (explorer.html)',
          'both': 'the flat report and the Explorer (report.html and explorer.html)'}


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
    for k in ('entity', 'groupBy', 'maxBuckets', 'maxResults', 'fields'):
        if k in q:
            args[k] = fill(q[k], run)
    if 'filters' in q:  # the servers take filters as a string holding a JSON array, not as the array
        args['filters'] = json.dumps(fill(q['filters'], run), ensure_ascii=False)
    return args


def queries():
    return json.load(open(HERE / 'recipes.json'))[RECIPE_DIR]['queries']


def slug(name):
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'tenant'


def cmd_plan(a):
    opt = dict(zip(a[0::2], a[1::2]))
    if '--tenant-id' not in opt or '--tenant-name' not in opt:
        sys.exit('plan needs --tenant-id and --tenant-name')
    if opt.get('--style') not in STYLES:
        sys.exit('plan needs --style report, --style explorer or --style both. Ask the user which style they want: the flat '
                 'report, to read through, print or send, or the Explorer, to look things up. Both show the same data.')
    if opt.get('--audience') not in AUDIENCES:
        sys.exit('plan needs --audience msp or --audience client. Ask the user who will read the report: their own team '
                 '(msp: it names Inspect 365 and links into it) or their client (client: no Inspect 365 name or link).')
    as_of = dt.datetime.now(dt.timezone.utc).date()
    run = {'recipeDir': RECIPE_DIR, 'recipe': RECIPE, 'tenantId': opt['--tenant-id'], 'tenantName': opt['--tenant-name'],
           'tenantSlug': slug(opt['--tenant-name']), 'asOf': as_of.isoformat(), 'style': opt['--style'],
           'audience': opt['--audience'],
           'environment': ENVIRONMENT, 'plugin': f'inspect365 {PLUGIN_VERSION}'}
    out = pathlib.Path(opt.get('--out', '.')).resolve()
    if out == HERE.parent or HERE.parent in out.parents:
        sys.exit(f'{out} is in the skill folder, which can be read-only and is replaced on update. '
                 'Pass --out with a folder you can write to, such as your working folder.')
    base = out / f'inspect365-{RECIPE}-{run["tenantSlug"]}-{run["asOf"]}'
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
    calls = [{'id': q['id'], 'tool': q['tool'], 'arguments': call_args(q, run)} for q in queries()]
    json.dump(calls, open(run_dir / 'calls.json', 'w'), indent=1)
    print(f'run folder: {run_dir}')
    print(f"style: {STYLES[run['style']]}")
    print(f"for: {'the MSP (names Inspect 365 and links into it)' if run['audience'] == 'msp' else 'the client (no Inspect 365 name or link)'}")
    print(f'{len(calls)} calls. Save each result to raw/<call ID>.json, then run: sharepoint_permissions.py save "{run_dir}" <call ID>')
    for c in calls:
        print(f"{c['id']} | {c['tool']} | {json.dumps(c['arguments'], ensure_ascii=False)}")


def read_result(path_or_text, is_text=False):
    text = path_or_text if is_text else pathlib.Path(path_or_text).read_text(encoding='utf-8')
    try:
        return unwrap(text.strip())
    except json.JSONDecodeError:
        return None


def join_pages(run_dir, qid, spec, first):
    """Page 1 plus raw/<qid>.2.json, .3.json ... joined in order; None while a page is still to fetch."""
    pages, n = [first], 1
    while pages[-1].get('nextPageToken'):
        n += 1
        path = run_dir / 'raw' / f'{qid}.{n}.json'
        if not path.exists():
            print(f"{qid}: page {n - 1} saved; the list continues. Call {spec['tool']} again with the same arguments plus "
                  f"pageToken set to the nextPageToken in the last page, exactly as returned, write the result to "
                  f"raw/{qid}.{n}.json, then run save again.")
            return None
        page = read_result(path)
        if not isinstance(page, dict) or 'results' not in page:
            sys.exit(f'{qid}: page {n} is not the JSON the tool returns; save it again exactly as returned')
        problems = filter_problems(run_dir, spec, page)
        if problems:
            sys.exit(f'{qid}: page {n} answered a different call ({"; ".join(problems)}). Fetch it again with the same arguments.')
        pages.append(page)
    if n == 1:
        return first
    inner = dict(pages[0])
    inner.pop('nextPageToken', None)
    for page in pages[1:]:
        inner['results'] = inner.get('results', []) + page['results']
        inner['resultCount'] = inner.get('resultCount', 0) + page.get('resultCount', len(page['results']))
    inner['pagesJoined'] = n
    return inner


def cmd_save(a):
    run_dir, qid = pathlib.Path(a[0]).resolve(), a[1]
    src = a[2] if len(a) > 2 else str(run_dir / 'raw' / f'{qid}.json')
    spec = {q['id']: q for q in queries()}
    if qid not in spec:
        sys.exit(f'{qid} is not a call in this run')
    inner = read_result(sys.stdin.read(), True) if src == '-' else read_result(src)
    if not isinstance(inner, dict):
        sys.exit(f'{qid}: the saved result is not the JSON the tool returns; save it again exactly as returned')
    if 'results' not in inner:
        text = str(inner.get('text') or inner)[:300]
        sys.exit(f'{qid}: the tool returned no results but this message: {text}')
    if spec[qid].get('firstPageOnly'):
        inner.pop('nextPageToken', None)  # only the newest record is wanted
    elif inner.get('nextPageToken'):
        inner = join_pages(run_dir, qid, spec[qid], inner)
        if inner is None:
            return
    try:
        print('saved', qid, save(run_dir, qid, inner), 'chars')
    except AssertionError as e:
        sys.exit(f'{qid}: {e}. The call did not match the plan; run it again exactly as printed and save it again.')


def missing(run_dir):
    return [q['id'] for q in queries() if not (run_dir / 'inputs' / f"{q['id']}.json").exists()]


def cmd_status(a):
    left = missing(pathlib.Path(a[0]).resolve())
    print('all calls saved' if not left else f'{len(left)} calls still to save: ' + ', '.join(left))


def cmd_build(a):
    run_dir = pathlib.Path(a[0]).resolve()
    left = missing(run_dir)
    if left:
        sys.exit(f'{len(left)} calls still to save: ' + ', '.join(left))
    b = subprocess.run([sys.executable, str(HERE / f'{RECIPE_DIR}_build.py'), str(run_dir)], capture_output=True, text=True)
    text = (b.stdout + b.stderr).strip()
    if b.returncode:
        if 'Traceback (most recent call last)' in text:
            text += ("\nThe build hit an error in this skill's scripts, not in the tenant's data. Tell the user the line above; "
                     "don't edit the scripts or the saved results.")
        sys.exit(text)
    print(text)


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] not in ('plan', 'save', 'status', 'build'):
        sys.exit(__doc__)
    {'plan': cmd_plan, 'save': cmd_save, 'status': cmd_status, 'build': cmd_build}[sys.argv[1]](sys.argv[2:])
