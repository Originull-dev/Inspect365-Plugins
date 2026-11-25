"""SharePoint permissions report recipe, v0.2.1: who can open each SharePoint site and each document library.

    python3 skills/inspect365-report-recipes/recipes/sharepoint_permissions/build.py <run-dir>

<run-dir>/run.json names the tenant, the environment, who will read the result ("audience": "msp" or "client") and
which style of report to make ("style": "report", "explorer" or "both"); <run-dir>/inputs/<id>.json holds the
response to each query in queries.json, saved exactly as returned, with a paged list's pages joined. The two styles
show the same data:

    report.html     the flat report: every site on one page, with one row per grant on the site and on each library
                    with its own permissions, to read top to bottom, print or save as a PDF
    explorer.html   the Explorer: the same access as a tree to move through, with filters, a search and a page per person

The MSP's copy names Inspect 365 and links each site, group, team and person into it. The client's copy has neither
the name nor a link, so it can go out under the MSP's own brand. No model is involved, and the same inputs always
give the same pages apart from the time printed in the flat report's footer. Standard library only.
"""
import contextlib
import io
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import access  # noqa: E402
import explorer  # noqa: E402

VERSION = '0.2.1'
STYLES = ('report', 'explorer', 'both')
APPS = {'us-production': 'https://us.inspect365.app', 'dev': 'https://dev.inspect365.app'}
IDS = ('sites', 'securables', 'roleAssignments', 'siteGroups', 'grants', 'levels', 'users', 'teams', 'groupInfo', 'latestRun')
WHOLE = set(IDS) - {'latestRun'}  # every list must be complete; only the newest collection run is read


def read_inputs(run_dir):
    d = {}
    for qid in IDS:
        path = run_dir / 'inputs' / f'{qid}.json'
        if not path.exists():
            sys.exit(f'{qid}: no saved result. Save every planned call before building.')
        inner = json.loads(path.read_text(encoding='utf-8'))
        rows = inner.get('results')
        if not isinstance(rows, list):
            sys.exit(f'{qid}: the saved result holds no list of results; save it again exactly as returned')
        total = inner.get('totalCount')
        if qid in WHOLE and total is not None and len(rows) != total:
            sys.exit(f'{qid}: the list holds {len(rows):,} rows of {total:,}. A page is missing: fetch it and save again.')
        if qid in WHOLE and len({r.get("id") for r in rows}) != len(rows):
            sys.exit(f'{qid}: the same record came back twice. A page was saved twice: fetch the pages again in order.')
        d[qid] = rows
    return d


def main(run_dir):
    run_dir = pathlib.Path(run_dir).resolve()
    run = json.loads((run_dir / 'run.json').read_text(encoding='utf-8'))
    audience = run.get('audience')
    if audience not in ('msp', 'client'):
        sys.exit('run.json has no audience. Plan the run again with --audience msp or --audience client.')
    msp = audience == 'msp'
    style = run.get('style') or 'both'  # a run folder from before the style was asked gets both
    if style not in STYLES:
        sys.exit('run.json has no style. Plan the run again with --style report, --style explorer or --style both.')
    d = read_inputs(run_dir)
    if not d['sites']:
        sys.exit('The tenant has no SharePoint sites in the collected data, so there is nothing to report.')
    if not d['securables']:
        sys.exit("No SharePoint permissions have been collected for this tenant, so who can open its sites and libraries isn't "
                 'known. The report needs a collection run that reads SharePoint permissions.')
    d['_meta'] = {'extracted': run.get('asOf'), 'recipe': f'sharepoint-permissions {VERSION}'}
    access.normalize(d)
    access.TENANT, access.TENANT_NAME = run['tenantId'], run['tenantName']
    access.APP = APPS.get(run.get('environment'), APPS['us-production'])
    access.DATA = access.REPO = run_dir
    access.load = lambda: d
    access.load_links = lambda: {'teams': d['teams']}  # each team's channels, for the Open in Teams link
    access.load_sharing = lambda: None
    for old in ('report.html', 'explorer.html'):  # a failed build must not leave an older page behind
        (run_dir / old).unlink(missing_ok=True)
    log = io.StringIO()
    with contextlib.redirect_stdout(log):  # the page build prints its own working lines; only some are for the reader
        access.build(list(access.DEFAULT_KINDS), msp)
    if msp:
        (run_dir / 'report-msp.html').replace(run_dir / 'report.html')
    data = explorer.explorer_data(d, msp=msp)  # also counts the groups with no one in them, for the line below
    made = []
    if style in ('report', 'both'):
        made.append('report.html')
    else:
        (run_dir / 'report.html').unlink()
    if style in ('explorer', 'both'):
        explorer.write(run_dir / 'explorer.html', data)
        made.append('explorer.html')
    s = None
    for line in log.getvalue().splitlines():
        if line.startswith(('collection:', 'level check:')):
            print(line)
        elif line.startswith('{"sites"'):  # the page build's own summary of what it listed
            s = json.loads(line)
    if s is None:
        sys.exit('The page build printed no summary; the pages may be incomplete.')
    empties = sum(len(v) for v in data['emp'].values())
    print(f"{s['kept']:,} sites listed, {s['archived']:,} archived with access unknown; {s['libraries']:,} document libraries, "
          f"{s['ownPermissions']:,} with their own permissions; {s['openToEveryoneSites']:,} sites and "
          f"{s['openToEveryoneLibraries']:,} libraries open to everyone in the organization; "
          f"{empties:,} groups that hold a level with no one in them")
    if not msp:  # the client's copy carries the vendor's name only where the tenant's own data holds it
        for name in made:
            if 'inspect365.app' in (run_dir / name).read_text(encoding='utf-8'):
                sys.exit(f"{name}: the client's copy holds a link into the app; it must not. Tell the user; don't edit the page.")
    print(f"sharepoint-permissions {VERSION}: {run['tenantName']}, for the {'MSP' if msp else 'client'}; "
          + ' and '.join(f"{name} {(run_dir / name).stat().st_size:,} bytes" for name in made))
    for name in made:
        print(f"{'report' if name == 'report.html' else 'explorer'}: {run_dir / name}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
