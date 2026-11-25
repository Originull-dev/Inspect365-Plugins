"""Check that every number in a recipe report's text is a recorded fact, and that no vendor name appears.

    python3 skills/inspect365-report-recipes/check_facts.py <run-dir> [<run-dir> ...]

Reads data-rendered.json and facts.json from each run. From every text field it removes the data
strings the build recorded (names, Microsoft labels, mapping labels), HTML tags, ids, dates and
version numbers, then requires each remaining number to equal a fact value, the length of a fact list,
or one of the constants that definitions name (window and bucket edges, "Microsoft 365").
The same stripped text, the report title and the rendered page outside its data must not name
Inspect 365: reports go out under the brand of whoever hands them over. Tenant data may still hold
the name (a guest domain, say), which is why the data strings are removed first.
Prints each problem with where it appears, and exits 1 if there is any.
"""
import html, json, pathlib, re, sys

CONSTANTS = {0, 7, 8, 30, 31, 45, 46, 90, 365}
SKIP_KEYS = {'pct', 'color', 'cls', 'tone', 'type', 'key', 'idx', 'render', 'schemaVersion', 'status', 'id'}
MONTHS = 'January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec'
NOISE = [re.compile(p) for p in (
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',      # ids
    r'\d{4}-\d{2}-\d{2}(?:T[\d:.]+Z?)?',                                     # ISO dates
    rf'\b(?:{MONTHS}) \d{{1,2}}, \d{{4}}', rf'\b(?:{MONTHS}) \d{{4}}',         # written dates
    r'\bv\d+(?:\.\d+)+', r'\bIG\d\b', r'Implementation Group \d',             # versions and framework names
)]
NUM = re.compile(r'(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\w.])')
VENDOR = re.compile(r'inspect\s*365', re.I)
PAGE_DATA = re.compile(r'(<script type="application/json" id="report-data">).*?(</script>)', re.S)


def fact_numbers(v, out):
    if isinstance(v, bool) or v is None:
        return
    if isinstance(v, (int, float)):
        out.add(float(v))
    elif isinstance(v, str):
        try:
            out.add(float(v.replace(',', '')))
        except ValueError:
            pass
    elif isinstance(v, list):
        out.add(float(len(v)))
        for x in v:
            fact_numbers(x, out)
    elif isinstance(v, dict):
        out.add(float(len(v)))
        for k, x in v.items():
            fact_numbers(k, out)
            fact_numbers(x, out)


def texts(node, path):
    if isinstance(node, dict):
        for k, v in node.items():
            if k not in SKIP_KEYS:
                yield from texts(v, f'{path}.{k}')
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from texts(v, f'{path}[{i}]')
    elif isinstance(node, str):
        yield path, node


def check(run_dir):
    doc = json.load(open(run_dir / 'data-rendered.json'))
    facts = json.load(open(run_dir / 'facts.json'))
    strings = sorted(facts.get('_strings', {}).get('value', []), key=len, reverse=True)
    allowed = {float(c) for c in CONSTANTS}
    for k, f in facts.items():
        if k != '_strings':
            fact_numbers(f['value'], allowed)
    stray = []
    for path, s in texts(doc['sections'], 'sections'):
        t = html.unescape(re.sub(r'<[^>]+>', ' ', s))
        for d in strings:  # longer data strings first, whole
            if len(d) > 3 and d in t:
                t = t.replace(d, ' ')
        for rx in NOISE:
            t = rx.sub(' ', t)
        for d in strings:  # short ones such as an OS version "12" only as whole tokens, never inside a date
            if d and len(d) <= 3:
                t = re.sub(rf'(?<![\w.:/-]){re.escape(d)}(?![\w.:/-])', ' ', t)
        ctx = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', s)))[:110]
        for m in NUM.findall(t):
            if float(m.replace(',', '')) not in allowed:
                stray.append((path, m, ctx))
        if VENDOR.search(t):
            stray.append((path, 'vendor name', ctx))
    manifest = run_dir / 'manifest.json'
    if manifest.exists():
        title = (json.load(open(manifest)).get('deck') or {}).get('title') or ''
        if VENDOR.search(title):
            stray.append(('manifest.deck.title', 'vendor name', title))
    page = run_dir / 'report.html'
    if page.exists():
        shell = re.sub(r'<title>.*?</title>', '', PAGE_DATA.sub(r'\1\2', page.read_text(encoding='utf-8')), flags=re.S)
        if VENDOR.search(shell):
            stray.append(('report.html', 'vendor name', 'in the page outside its data'))
    return stray


if __name__ == '__main__':
    failed = False
    for arg in sys.argv[1:]:
        run_dir = pathlib.Path(arg).resolve()
        stray = check(run_dir)
        print(f'{run_dir.parent.name}/{run_dir.name}: ' + ('every number is a recorded fact and no vendor name appears' if not stray else f'{len(stray)} problems'))
        for path, m, ctx in stray:
            print(f'   {m!r} at {path}: {ctx}')
        failed |= bool(stray)
    sys.exit(1 if failed else 0)
