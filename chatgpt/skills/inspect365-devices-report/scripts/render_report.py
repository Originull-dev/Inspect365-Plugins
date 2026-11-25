"""Render a recipe run into one self-contained report.html.

    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>] [--out <file>]

Embeds <run-dir>/data-rendered.json in report-template.html. With no --brand, <run-dir>/brand.json is
used if it exists; with neither, the page carries no branding at all.

A brand profile belongs to whoever hands the report over, such as an MSP. It sets the header, the
separators and the footer, never the data, so data-rendered.json is the same with or without one:

    {
      "name": "Example Managed Services",      shown in the header and the footer line
      "tagline": "IT and security",             under the name
      "logo": "logo.png",                       PNG, JPEG, GIF, WebP or SVG next to the profile, or a data: URI
      "logoHeight": 36,                         pixels, 16 to 96
      "headerBackground": "#12304f",            header band color; text turns white or black to suit it
      "headerText": "light",                    optional override: "light" or "dark"
      "accent": "#e0a526",                      separator under the header, part dividers, footer rule
      "footer": "Confidential. Prepared for the client named above."
    }

Every field is optional. Standard library only: the Copilot script sandbox has no network and no
package installs.
"""
import base64, html, json, pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
TEMPLATE = HERE / 'report-template.html'
FIELDS = ('name', 'tagline', 'logo', 'logoHeight', 'headerBackground', 'headerText', 'accent', 'footer')
HEX = re.compile(r'^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$')
LOGO_TYPES = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
              '.webp': 'image/webp', '.svg': 'image/svg+xml'}
DATA_URI = re.compile(r'^data:image/(?:png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$')
MAX_LOGO = 512 * 1024


class BrandError(ValueError):
    pass


def logo_uri(value, base):
    if value.startswith('data:'):
        if not DATA_URI.match(value):
            raise BrandError('logo: a data URI must be a base64 PNG, JPEG, GIF, WebP or SVG image')
        return value
    path = (base / value).resolve()
    kind = LOGO_TYPES.get(path.suffix.lower())
    if not kind:
        raise BrandError(f'logo: {path.name} is not a PNG, JPEG, GIF, WebP or SVG file')
    if not path.is_file():
        raise BrandError(f'logo: {path} not found')
    data = path.read_bytes()
    if len(data) > MAX_LOGO:
        raise BrandError(f'logo: {path.name} is {len(data) // 1024} KB; use a file under {MAX_LOGO // 1024} KB')
    return f'data:{kind};base64,' + base64.b64encode(data).decode('ascii')


def load_brand(path):
    """Read and check a brand profile; return the brand object the template reads."""
    path = pathlib.Path(path).resolve()
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        raise BrandError(f'{path.name}: {e}')
    if not isinstance(raw, dict):
        raise BrandError(f'{path.name}: expected a JSON object')
    unknown = sorted(set(raw) - set(FIELDS))
    if unknown:
        raise BrandError(f'{path.name}: unknown fields {", ".join(unknown)}; allowed: {", ".join(FIELDS)}')
    brand = {}
    for k in ('name', 'tagline', 'footer'):
        if raw.get(k) not in (None, ''):
            brand[k] = str(raw[k]).strip()
    for k in ('headerBackground', 'accent'):
        if raw.get(k) not in (None, ''):
            if not isinstance(raw[k], str) or not HEX.match(raw[k]):
                raise BrandError(f'{k}: use a hex color such as #12304f')
            brand[k] = raw[k]
    if raw.get('headerText') not in (None, ''):
        if raw['headerText'] not in ('light', 'dark'):
            raise BrandError('headerText: use "light" or "dark"')
        brand['headerText'] = raw['headerText']
    if raw.get('logoHeight') is not None:
        h = raw['logoHeight']
        if isinstance(h, bool) or not isinstance(h, int) or not 16 <= h <= 96:
            raise BrandError('logoHeight: use a whole number of pixels from 16 to 96')
        brand['logoHeight'] = h
    if raw.get('logo') not in (None, ''):
        brand['logo'] = logo_uri(str(raw['logo']), path.parent)
    return brand


def title_for(run_dir, doc):
    m = {}
    if (run_dir / 'manifest.json').exists():
        m = json.loads((run_dir / 'manifest.json').read_text(encoding='utf-8'))
    tenant = (m.get('tenant') or {}).get('name') or doc.get('tenantName', '')
    label = (m.get('deck') or {}).get('title') or doc.get('deckType', '')
    return ' · '.join(p for p in (tenant, label, doc.get('asOf', '')) if p) or 'Report'


def render(run_dir, brand_path=None, out=None):
    """Write the report page; return its path. brand_path=None uses <run-dir>/brand.json if present."""
    run_dir = pathlib.Path(run_dir).resolve()
    doc = json.loads((run_dir / 'data-rendered.json').read_text(encoding='utf-8'))
    if brand_path is None and (run_dir / 'brand.json').exists():
        brand_path = run_dir / 'brand.json'
    if brand_path:
        doc['brand'] = load_brand(brand_path)
    else:
        doc.pop('brand', None)
    template = TEMPLATE.read_text(encoding='utf-8')
    head, sep, tail = template.partition('id="report-data">')
    if not sep or '__DATA__' not in tail or '__TITLE__' not in head:
        raise RuntimeError(f'{TEMPLATE.name} is missing its title or data placeholder')
    # Escaping "<" keeps every string in the JSON from closing or confusing the script element.
    payload = json.dumps(doc, ensure_ascii=False).replace('<', '\\u003c')
    page = head.replace('__TITLE__', html.escape(title_for(run_dir, doc)), 1) + sep + tail.replace('__DATA__', payload, 1)
    out_path = pathlib.Path(out).resolve() if out else run_dir / 'report.html'
    out_path.write_text(page, encoding='utf-8')
    return out_path


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or args[0].startswith('-'):
        sys.exit(__doc__)
    opts = dict(zip(args[1::2], args[2::2]))
    unknown = sorted(set(opts) - {'--brand', '--out'})
    if unknown or len(args) % 2 == 0:
        sys.exit(__doc__)
    try:
        print(f"rendered {render(args[0], opts.get('--brand'), opts.get('--out'))}")
    except BrandError as e:
        sys.exit(f'brand profile: {e}')
