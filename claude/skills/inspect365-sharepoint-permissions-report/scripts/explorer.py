"""The Explorer: the SharePoint permissions report as one page to move through, from the same model as the flat report.

A tree of sites, subsites and document libraries on the left, grouped by what each site is connected to, with filters
for unique permissions and for access by everyone in the organization; the selected site's or library's access on the
right, as SharePoint grants it. explorer_data() turns the model into the page's data (people once, each group's people
once, each web's or library's grants once) and write() puts it into the template, explorer.html, as one self-contained
file. The numbering of people and groups is fixed by sorting, so the same data always gives the same file.
"""
import json
import pathlib

if 'ref' not in globals():  # a caller that runs this source in its own namespace brings its own copy of the model
    import access as ref

TEMPLATE = pathlib.Path(__file__).resolve().parent / 'explorer.html'


def explorer_data(d, include_teams=True, msp=False, show=('sp', 'group')):
    """The explorer's page data: people once, each group's people once, and per web or library only its grants."""
    m = ref.Model(d)
    for s in d['sites']:  # same naming rule as the report
        if not (s.get('displayName') or '').strip():
            path = '/' + (s.get('webUrl') or '').split('.sharepoint.com/', 1)[-1]
            s['displayName'] = f"{s.get('usageReport.rootWebTemplate') or 'Site'} at {path}"
    kept, excluded, archived, kinds = m.listed(include_teams)
    people, pid, groups, gid, acc = [], {}, [], {}, {}
    emp = {}  # per web or library: SharePoint groups granted a level there with no one in them

    def person(key):
        if key not in pid:
            p = m.people_reg[key]
            pid[key] = len(people)
            people.append({'n': p['name'], 'u': p['upn'], 'g': int(p['external']), 'd': int(p['disabled']), 'x': int(p['notInDirectory'])})
            if msp and p.get('oid'):
                people[-1]['iu'] = ref.app_url('identity', p['oid'])
        return pid[key]

    def group(gk):
        if gk not in gid:
            gid[gk] = len(groups)
            groups.append(gk)
        return gid[gk]

    def access(sec):
        """A web's or library's own grants, stored once: [kind, name, role, level, tier, note, people, groups, specials, partial]."""
        if sec and sec['id'] not in acc:
            acc[sec['id']] = [[{'sp': 'g', 'direct': 'd', 'admin': 'a'}[r['kind']], r['name'], (r['role'] or '')[:1], r['level'], r['tier'],
                               r['note'] or '', sorted(person(k) for k in sorted(r['people'], key=str)), [group(gk) for gk in r['groups']],
                               [[sp['family'], sp['title']] for sp in r['specials']], int(r['partial'])] for r in m.rows(sec)['rows']]
            empties = [[r['name'], (r['role'] or '')[:1], r['level'], r['tier'], r['note'] or '', r['members'],
                        ref._join(r['system']) if r['system'] and r['members'] == len(r['system']) else ''] for r in m.empty_groups(sec)]
            if empties:
                emp[sec['id']] = empties
        return (sec or {}).get('id')

    sites_out, unread = [], []
    for s in kept:
        k, root = kinds[s['id']], m.root(s['id'])
        name = s.get('displayName') or s.get('webUrl')
        if not root or root.get('siteStatus.status') != 'ok':
            unread.append({'n': name, 'url': s.get('webUrl')})
            continue
        access(root)
        webs, libs = [], []
        for w in sorted((x for x in m.by_site[s['id']] if x.get('kind') == 'web' and not x.get('isRootWeb')),
                        key=lambda x: (x.get('webUrl') or '').lower()):
            src, inh = m.effective(w)
            row = {'id': w['id'], 'n': w.get('webTitle'), 'url': w.get('webUrl'), 'wid': w.get('webId'), 'own': int(not inh),
                   'src': access(src)}
            if not inh:
                access(w)
                row['cmp'] = access(m.compare_web(w))
            webs.append(row)
        for x in sorted((x for x in m.by_site[s['id']] if x.get('kind') == 'library' and not x.get('isSystemLibrary')),
                        key=lambda x: (not (x.get('webId') == root.get('webId')), (x.get('listTitle') or '').lower())):
            src, inh = m.effective(x)
            row = {'id': x['id'], 'n': x.get('listTitle'), 'url': x.get('listUrl'),
                   'web': None if x.get('webId') == root.get('webId') else x.get('webTitle'), 'wid': x.get('webId'),
                   'own': int(not inh), 'src': access(src)}
            if not inh:
                access(x)
                row['cmp'] = access(m.compare_web(x))
            libs.append(row)
        c = m.connection(s, k)  # what the site is connected to
        sites_out.append({'id': s['id'], 'n': name, 'url': s.get('webUrl'), 'c': c['cat'], 'kn': c['label'], 'dt': c['detail'],
                          'cn': c['connected'], 'ax': c['access'], 'tu': c['teams_url'],
                          'iu': c['site_app'] if msp else None, 'gu': c['group_app'] if msp else None, 'pub': int(m.is_public(s)),
                          'teams': {'teams': 1, 'channel': 2}.get(k, 0), 'root': root['id'],
                          'read': (root.get('siteStatus.lastSucceededAt') or '')[:10], 'webs': webs, 'libs': libs})
    groups_out = []
    for gk in groups:  # after every web and library is read, so each group's people are complete
        info = m.group_reg[gk]
        groups_out.append({'k': {'m365Group': 'm', 'directoryRole': 'r'}.get(info['kind'], 'e'), 'c': (info['claim'] or '')[:1],
                           'n': m.group_name(gk), 'm': sorted(person(k) for k in sorted(info['members'], key=str)),
                           'x': 2 if info['expansion'] == 'unresolved' else 0 if info['members'] else 1})
    read = sorted({(r.get('siteStatus.collectedAt') or '')[:16].replace('T', ' ') for r in d['securables']
                   if r.get('isRootWeb') and r.get('siteStatus.collectedAt')})
    return {'tenant': ref.TENANT_NAME, 'read': read[-1] if read else '', 'membersEnabled': m.members_enabled, 'people': people,
            'groups': groups_out, 'acc': acc, 'emp': emp, 'sites': sites_out, 'unread': unread, 'msp': int(msp), 'show': list(show),
            'vendor': 'Inspect 365' if msp else '', 'run': ref.latest_run_note(d),
            'cats': [[c, label] for c, label in ref.CATEGORIES],
            'archived': [{'n': s.get('displayName') or s.get('webUrl'), 'url': s.get('webUrl')} for s in archived],
            'excluded': [{'n': s.get('displayName') or s.get('webUrl'), 'k': 'Teams channel site' if kinds[s['id']] == 'channel' else 'Teams-connected site'}
                         for s in excluded]}


def explorer_counts(data):
    own = lambda rows: sum(r['own'] for r in rows)
    out = {}
    for label, sites in (('listed', [s for s in data['sites'] if not s['teams']]), ('with Teams', data['sites'])):
        out[label] = {'sites': len(sites), 'libraries': sum(len(s['libs']) for s in sites), 'uniqueLibraries': sum(own(s['libs']) for s in sites),
                      'uniqueSubsites': sum(own(s['webs']) for s in sites)}
    return {**out, 'people': len(data['people']), 'groups': len(data['groups']), 'websAndLibrariesWithOwnGrants': len(data['acc']),
            'grantRows': sum(len(v) for v in data['acc'].values())}


def write(out, data, template=None):
    """The page: the template with the data put in."""
    blob = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    out.write_text(pathlib.Path(template or TEMPLATE).read_text().replace('/*DATA*/', 'window.SP = ' + blob + ';'))
    return out
