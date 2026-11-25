"""Tenant overview recipe, v0.3.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/tenant_overview/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

The one report that covers the whole tenant at less depth, for prospects and customers alike: the working set,
open and accepted findings by area, the checks with the most open findings, the latest Microsoft Secure Score
snapshot, high-impact users and their devices, and object counts. Every input comes from one collection run, as on
a prospect's first pull (2026-10-07): aggregates, the latest Secure Score snapshot, the Secure Score recommended
actions below their maximum points (0.3.0: "the secure score recommendations by area"), and three lists for the
high-impact section, the only part that names users and devices. Five deep dives cover the areas in full; the
report names the one for each area. Facts only and no vendor branding (README). The same inputs always produce the
same bytes.
"""
import html, pathlib, re, sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import ASSET, IMPACT_REASON, PILLAR, STATUS_NOTE, Report, esc, n, num  # noqa: E402

R = Report(__file__, 'tenant-overview', '0.3.0', 'Tenant overview')
D, fact = R.D, R.fact

# ---------------------------------------------------------------- fixed tables
# Each deep dive: the finding types (asset types) it covers in full, and its report title.
AREAS = [('Users and groups', ['Identity', 'Group'], 'Users and groups report'),
         ('Devices', ['Device'], 'Devices report'),
         ('Entra apps', ['ServicePrincipal'], 'Entra apps report'),
         ('Installed software', ['InstalledSoftware'], 'Installed software report'),
         ('Mailboxes, Teams and SharePoint', ['Mailbox', 'Team', 'SharePoint'], 'Mailboxes, Teams and SharePoint report')]
TYPES = [t for _, types, _ in AREAS for t in types]
TOP_N = 10
DEVICE_ROWS = fact('rules.highImpactDeviceRows', 10, 'recipe rule: high-impact devices listed at most')
# Microsoft tenants that publish apps, from references/app-classification-convention.md, as in the Entra apps report.
# apps_other_publishers repeats the list in its filters; the build checks the two agree.
MICROSOFT_TENANTS = ['f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47',
                     'cdc5aeea-15c5-4db6-b079-fcadd2505dc2', '33e01921-4d64-4f8c-a055-5bdaffd5e33d',
                     '0d933fb8-3f65-4722-9430-08d60fc88af4', '975f013f-7f24-47e8-a7d3-abc4752bf346',
                     '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8']
# Microsoft's labels for field values: Exchange admin center mailbox types, Teams visibility, Entra policy state.
MAILBOX = {'UserMailbox': 'User mailbox', 'SharedMailbox': 'Shared mailbox', 'GroupMailbox': 'Group mailbox',
           'RoomMailbox': 'Room mailbox', 'EquipmentMailbox': 'Equipment mailbox', 'SchedulingMailbox': 'Scheduling mailbox',
           'DiscoveryMailbox': 'Discovery mailbox', 'LinkedMailbox': 'Linked mailbox'}
TEAM_VIS = {'public': 'Public', 'private': 'Private', 'hiddenMembership': 'Hidden membership'}
CA_STATE = {'enabled': 'On', 'enabledForReportingButNotEnforced': 'Report-only', 'disabled': 'Off'}
# The Defender portal's device inventory labels for the machine API's exposureLevel values (Learn, 2026-10-07).
EXPOSURE_LEVEL = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'None': 'No data available'}
EXPOSURE = 'Defender exposure score'
# Why the product marks a user or a device high impact (system.impactSources[].type), in table order.
USER_REASONS = ['privilegedDirectoryRole', 'orgChart', 'manualAssignment']
DEVICE_REASONS = ['inherited', 'manualAssignment']

other_q = next(q for q in R.spec['queries'] if q['id'] == 'apps_other_publishers')
if sorted(f['value'] for f in other_q['filters'] if f['field'] == 'appOwnerOrganizationId' and f['operator'] == 'ne') \
        != sorted(MICROSOFT_TENANTS + ['{tenantId}']):
    sys.exit('apps_other_publishers and MICROSOFT_TENANTS list different tenants')


def os_family(v):
    """Operating system family for the overview; the Devices report shows the reported names."""
    s = str(v).lower()
    if s.startswith('windows'):
        return 'Windows'
    if s.startswith('android'):
        return 'Android'
    if s in ('ios', 'ipados', 'ipad', 'iphone'):
        return 'iOS and iPadOS'
    if s.startswith('mac'):
        return 'macOS'
    return str(v)


truthy = lambda v: str(v).lower() == 'true'


# ---------------------------------------------------------------- helpers
def complete(qid):
    if R.IN[qid].get('omittedBucketCount'):
        sys.exit(f'{qid} left out {R.IN[qid]["omittedBucketCount"]} buckets: raise its maxBuckets')
    return R.IN[qid]


def counts(qid, label=str, order=()):
    """One aggregate as a complete composition [(label, count)]: the labels in `order` first (zeros kept), then
    the rest by count and label. Records with no value count as 'No value'."""
    d, c = complete(qid), Counter()
    for b in d.get('results', []):
        c[D(label(b['value']))] += b['count']
    if d.get('nullOrMissingCount'):
        c['No value'] += d['nullOrMissingCount']
    if sum(c.values()) != d['totalCount']:
        sys.exit(f'{qid}: buckets add up to {sum(c.values())}, not its total {d["totalCount"]}')
    rest = sorted(((k, v) for k, v in c.items() if k not in order), key=lambda kv: (-kv[1], kv[0]))
    return [(k, c.get(k, 0)) for k in order] + rest


def same(a, b, what):
    if a != b:
        sys.exit(f'{what}: {a} != {b}. The inputs come from different collections; run the queries again')


joined = lambda parts: ' · '.join(f'{k} {n(v)}' for k, v in parts)
pct1 = lambda x: f'{x:.1f}%'


def breakdown(parts, source=None, raw=None):
    """A breakdown cell: Microsoft's labels with their counts, and beneath them the source's own values in the same
    order (2026-10-07: never a raw value alone, and never a label without the value it stands for)."""
    cell = {'text': joined(parts)}
    if source:
        cell['sub'] = f'{source}: ' + ' · '.join(D(raw.get(k, 'null' if k == 'No value' else k)) for k, _ in parts)
    return cell


def reasons(rec):
    return list(rec.get('system.impactSources[].type') or [])


# ---------------------------------------------------------------- findings
DEFS = {d['id']: d for d in R.IN['definitions']['definitions']}
fact('definitions.count', len(DEFS), 'definitions')
for q in ('findings_open_by_type', 'findings_accepted_by_type', 'findings_open_by_check'):
    complete(q)
o_type, a_type, o_check = R.buckets('findings_open_by_type'), R.buckets('findings_accepted_by_type'), R.buckets('findings_open_by_check')
stray = sorted(t for t in {*o_type, *a_type} if t not in TYPES)
if stray:
    sys.exit(f'finding types with no area: {stray}. Add them to AREAS')
unknown = sorted(f for f in o_check if f not in DEFS)
if unknown:
    sys.exit(f'findings_open_by_check holds finding ids with no definition: {unknown}')
open_total = fact('findings.open', R.total('findings_open_by_type'), 'findings_open_by_type')
acc_total = fact('findings.accepted', R.total('findings_accepted_by_type'), 'findings_accepted_by_type')
same(sum(o_type.values()), open_total, 'open findings by type')
same(sum(a_type.values()), acc_total, 'accepted findings by type')
from_checks = Counter()
for f, c in o_check.items():
    from_checks[DEFS[f]['type']] += c
same({t: c for t, c in from_checks.items() if c}, {t: c for t, c in o_type.items() if c}, 'open findings by check, summed by type')

share = lambda x: round(100 * x / open_total, 1) if open_total else 0.0
ranked = sorted((f for f in o_check if o_check[f]),
                key=lambda f: (-o_check[f], TYPES.index(DEFS[f]['type']), DEFS[f]['orderId'], DEFS[f]['displayName']))
fact('findings.openByCheck', [{'check': DEFS[f]['displayName'], 'type': DEFS[f]['type'], 'open': o_check[f]} for f in ranked],
     'findings_open_by_check + definitions')
fact('findings.checksWithOpen', len(ranked), 'findings_open_by_check')

area_facts, area_rows = {}, []
for name, types, report in AREAS:
    op, ac = sum(o_type.get(t, 0) for t in types), sum(a_type.get(t, 0) for t in types)
    top = next((f for f in ranked if DEFS[f]['type'] in types), None)
    area_facts[name] = {'open': op, 'accepted': ac, 'share': share(op),
                        'topCheck': DEFS[top]['displayName'] if top else None, 'topCheckOpen': o_check[top] if top else 0}
    area_rows.append({'area': {'text': name, 'sub': ('Asset types: ' if len(types) > 1 else 'Asset type: ') + ', '.join(ASSET[t] for t in types)},
                      'open': n(op), 'acc': n(ac), 'share': pct1(share(op)),
                      'top': {'text': D(DEFS[top]['displayName']), 'sub': f'{n(o_check[top])} open'} if top else {'text': 'None open'},
                      'report': {'text': report}})
fact('findings.byArea', area_facts, 'findings_open_by_type + findings_accepted_by_type + findings_open_by_check + definitions')
all_share = fact('findings.byArea.allShare', 100.0 if open_total else 0.0, 'findings_open_by_type')
area_rows.append({'area': {'text': 'All areas'}, 'open': n(open_total), 'acc': n(acc_total), 'share': pct1(all_share)})
lead = max(AREAS, key=lambda a: (area_facts[a[0]]['open'], -AREAS.index(a)))

top = ranked[:TOP_N]
fact('findings.topChecks', [{'check': DEFS[f]['displayName'], 'open': o_check[f], 'share': share(o_check[f])} for f in top],
     'findings_open_by_check + definitions')
top_open = fact('findings.topChecks.open', sum(o_check[f] for f in top), 'findings_open_by_check')
top_share = fact('findings.topChecks.share', share(top_open), 'findings_open_by_check')

# ---------------------------------------------------------------- Microsoft Secure Score: the latest snapshot only
# One snapshot per collection run (createdDateTime is when the collector captured it), so a change over time needs
# runs a prospect's first pull doesn't have. 2026-10-07: the report shows the latest snapshot and no change.
ss = R.IN['secure_score']
if ss.get('mode') != 'current':
    sys.exit('secure_score is not a current-mode response: run it with no filter')
snap = ss.get('snapshot') or {}
taken = D(str(snap['createdDateTime'])[:10]) if snap.get('createdDateTime') else None
MEASURES = [('Overall', 'currentScore', 'maxScore', 'scorePercentage')] + [
    (PILLAR[p], f'{p}Score', f'max{p[0].upper()}{p[1:]}Score', f'{p}ScorePercentage') for p in ('identity', 'device', 'app', 'data')]
now = {}
for label, s, m, p in MEASURES:
    if snap.get(s) is not None and snap.get(m) is not None and snap.get(p) is not None:
        now[label] = {'points': round(float(snap[s]), 2), 'max': round(float(snap[m]), 2), 'percent': round(100 * float(snap[p]), 1)}
if snap.get('defenderExposureScore') is not None:
    now[EXPOSURE] = {'points': round(float(snap['defenderExposureScore']), 1), 'max': round(float(snap.get('maxDefenderExposureScore') or 100), 2)}
fact('secureScore.latest', now, 'secure_score')
score_rows = []
for label, v in now.items():
    if label == EXPOSURE:
        score_rows.append({'measure': {'text': EXPOSURE, 'sub': 'Microsoft Defender Vulnerability Management, 0 to 100; lower means less exposure'},
                           'points': f'{v["points"]:.1f}', 'max': num(v['max'])})
    else:
        score_rows.append({'measure': {'text': label if label == 'Overall' else f'{label} category'},
                           'points': num(v['points']), 'max': num(v['max']), 'percent': pct1(v['percent'])})

for q in ('controls_below_max_by_category', 'controls_scored_by_category'):
    complete(q)
below, scored = R.buckets('controls_below_max_by_category'), R.buckets('controls_scored_by_category')
CAT_ORDER = [PILLAR[p] for p in ('identity', 'device', 'app', 'data')]
cats = [c for c in CAT_ORDER if c in scored or c in below] + sorted(c for c in {*scored, *below} if c not in CAT_ORDER)
fact('secureScore.controls', {D(c): {'belowMax': below.get(c, 0), 'scored': scored.get(c, 0)} for c in cats},
     'controls_below_max_by_category + controls_scored_by_category')
below_total = fact('secureScore.controls.belowMax', R.total('controls_below_max_by_category'), 'controls_below_max_by_category')
scored_total = fact('secureScore.controls.scored', R.total('controls_scored_by_category'), 'controls_scored_by_category')
control_rows = [{'cat': {'text': c}, 'below': n(below.get(c, 0)), 'scored': n(scored.get(c, 0))} for c in cats]
control_rows.append({'cat': {'text': 'All categories'}, 'below': n(below_total), 'scored': n(scored_total)})

# The recommended actions themselves, by Microsoft's category. Learn (defender-xdr/microsoft-secure-score-improvement-actions)
# names the portal statuses; the Graph values of controlStateUpdates[].state are matched to them by name. An action below its
# maximum with no status set reads To address, as in the portal.
ACTION_STATUS = {'Default': 'To address', 'Planned': 'Planned', 'Ignored': 'Risk accepted',
                 'ThirdParty': 'Resolved through third party', 'AlternateMitigation': 'Resolved through alternate mitigation'}
STEPS = re.compile(r'\s*(?:To activate this setting, take the following steps\.|'
                   r'Please follow next steps to correctly configure the control\.)\s*$')


def implementation_status(s):
    """Microsoft's implementation status for the action, as plain text: list items joined, tags dropped, and the closing
    pointer to steps the portal shows left out, since the report does not carry them."""
    t = html.unescape(str(s or '')).replace('\xa0', ' ')
    t = re.sub(r'\s*</li>\s*<li>\s*', '; ', t)
    t = re.sub(r'\s*</p>\s*<ul>\s*<li>\s*', ': ', t)
    t = re.sub(r'\s*</li>\s*</ul>\s*', '. ', t)
    return STEPS.sub('', re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', t)).strip())


def action_status(c):
    """The latest status set on the action (controlStateUpdates[], by update time, then list order)."""
    states, dates = c.get('controlStateUpdates[].state') or [], c.get('controlStateUpdates[].updatedDateTime') or []
    if not states:
        return 'Default'
    return max(enumerate(states), key=lambda i: (str(dates[i[0]] or '') if i[0] < len(dates) else '', i[0]))[1]


ACTIONS = R.rows('secure_score_actions')
same(len(ACTIONS), R.total('secure_score_actions'), 'secure_score_actions rows saved')
for c in ACTIONS:
    if action_status(c) not in ACTION_STATUS:
        sys.exit(f'secure_score_actions holds status {action_status(c)!r}: add its Secure Score portal label to ACTION_STATUS')
by_cat = defaultdict(list)
for c in ACTIONS:
    by_cat[c.get('controlCategory') or 'No category'].append(c)
same(sorted(by_cat), sorted(c for c in cats if below.get(c)), 'categories with recommended actions below maximum')
for c in cats:
    same(len(by_cat.get(c, [])), below.get(c, 0), f'recommended actions below maximum in {c}')
    by_cat[c].sort(key=lambda a: (-(float(a['maxScore']) - float(a['controlScore.score'])), a.get('rank') or 999, a['title'].strip()))
fact('secureScore.actions', {D(c): [{'id': a['id'], 'points': round(float(a['controlScore.score']), 2), 'max': round(float(a['maxScore']), 2),
                                     'status': action_status(a)} for a in by_cat[c]] for c in cats if by_cat.get(c)},
     'secure_score_actions')


def action_panel(cat):
    acts = by_cat[cat]
    with_status = any(action_status(a) != 'Default' for a in acts)
    cols = [{'key': 'action', 'label': 'Recommended action'}, {'key': 'service', 'label': 'Service'}]
    cols += [{'key': 'status', 'label': 'Status'}] if with_status else []
    cols += [{'key': 'points', 'label': 'Points', 'n': True}, {'key': 'max', 'label': 'Maximum', 'n': True}]
    rows = []
    for a in acts:
        status = implementation_status(a.get('controlScore.implementationStatus'))
        row = {'action': {'text': D(a['title'].strip()), 'sub': D(status)} if status else {'text': D(a['title'].strip())},
               'service': {'mono': D(a.get('service') or '')}, 'points': num(a['controlScore.score']), 'max': num(a['maxScore'])}
        if with_status:
            row['status'] = R.state(ACTION_STATUS[action_status(a)], action_status(a), 'Secure Score')
        rows.append(row)
    return {'kicker': f'{cat}: {n(len(acts))} below their maximum points', 'cols': cols, 'rows': rows,
            'note': 'Beneath each action: its implementation status as Microsoft words it. Sorted by points not earned.'
                    + (' Status: as set in Secure Score; an action with none reads To address.' if with_status else '')}

# ---------------------------------------------------------------- environment
ut = counts('users_by_type')
accounts = fact('users.accounts', R.total('users_by_type'), 'users_by_type')
members, guests = fact('users.members', dict(ut).get('Member', 0), 'users_by_type'), fact('users.guests', dict(ut).get('Guest', 0), 'users_by_type')
me = counts('members_by_enabled', lambda v: 'Enabled' if truthy(v) else 'Disabled', ('Enabled', 'Disabled'))
same(R.total('members_by_enabled'), members, 'members by enabled state')
enabled = fact('users.membersEnabled', dict(me)['Enabled'], 'members_by_enabled')
disabled = fact('users.membersDisabled', dict(me)['Disabled'], 'members_by_enabled')

groups = fact('groups.byType', dict(counts('groups_by_type')), 'groups_by_type')
groups_total = fact('groups.total', R.total('groups_by_type'), 'groups_by_type')
own = fact('devices.byOwnership', dict(counts('devices_by_ownership', order=('Corporate', 'Personal', 'Unknown'))), 'devices_by_ownership')
devices = fact('devices.total', R.total('devices_by_ownership'), 'devices_by_ownership')
activity = fact('devices.corporateByActivity', dict(counts('corporate_by_inactive', lambda v: 'Inactive' if truthy(v) else 'Active',
                                                            ('Active', 'Inactive'))), 'corporate_by_inactive')
same(R.total('corporate_by_inactive'), own['Corporate'], 'corporate devices by activity')
os_counts = fact('devices.byOperatingSystem', dict(counts('devices_by_os', os_family)), 'devices_by_os')
same(R.total('devices_by_os'), devices, 'devices by operating system')
families = {}
for b in sorted(R.rows('devices_by_os'), key=lambda b: (-b['count'], str(b['value']))):
    families.setdefault(os_family(b['value']), []).append(D(b['value']))
merged = [(k, v) for k, v in sorted(families.items(), key=lambda kv: (-os_counts[kv[0]], kv[0])) if v != [k]]

apps = fact('apps.byCategory', dict(counts('apps_by_category')), 'apps_by_category')
sps = fact('apps.total', R.total('apps_by_category'), 'apps_by_category')
other_pub = fact('apps.otherPublishers', R.total('apps_other_publishers'), 'apps_other_publishers')
sw = R.IN['software_by_name']
sw_names = fact('software.distinctNames', sw.get('bucketCount', 0) + sw.get('omittedBucketCount', 0), 'software_by_name')
sw_records = fact('software.records', sw['totalCount'], 'software_by_name')
mbx_parts = counts('mailboxes_by_type', lambda v: MAILBOX.get(v, str(v)))
mbx = fact('mailboxes.byType', dict(mbx_parts), 'mailboxes_by_type')
mbx_total = fact('mailboxes.total', R.total('mailboxes_by_type'), 'mailboxes_by_type')
team_parts = counts('teams_by_visibility', lambda v: TEAM_VIS.get(v, str(v)), ('Public', 'Private'))
teams = fact('teams.byVisibility', dict(team_parts), 'teams_by_visibility')
teams_total = fact('teams.total', R.total('teams_by_visibility'), 'teams_by_visibility')
site_parts = counts('sites_by_personal', lambda v: 'OneDrive accounts' if truthy(v) else 'SharePoint sites', ('SharePoint sites', 'OneDrive accounts'))
sites = fact('sites.byKind', dict(site_parts), 'sites_by_personal')
sites_total = fact('sites.total', R.total('sites_by_personal'), 'sites_by_personal')
ca_parts = counts('ca_by_state', lambda v: CA_STATE.get(v, str(v)), ('On', 'Report-only', 'Off'))
ca = fact('conditionalAccess.byState', dict(ca_parts), 'ca_by_state')
ca_total = fact('conditionalAccess.total', R.total('ca_by_state'), 'ca_by_state')

inverse = lambda table: {v: k for k, v in table.items()}
ENV = [('User accounts', 'By user type', accounts, breakdown(ut), 'Users and groups report'),
       ('Member accounts', 'By account state', members,
        breakdown(me, 'Entra accountEnabled', {'Enabled': 'true', 'Disabled': 'false'}), 'Users and groups report'),
       ('Groups', 'By group type', groups_total, breakdown(groups.items()), 'Users and groups report'),
       ('Conditional Access policies', 'By state', ca_total, breakdown(ca_parts, 'Entra', inverse(CA_STATE)), 'Users and groups report'),
       ('Devices', 'By ownership', devices, breakdown(own.items()), 'Devices report'),
       ('Corporate devices', 'By last contact', own['Corporate'], breakdown(activity.items()), 'Devices report'),
       ('Devices', 'By operating system', devices, breakdown(os_counts.items()), 'Devices report'),
       ('Entra apps', 'Service principals by category', sps, breakdown(apps.items()), 'Entra apps report'),
       ('Installed software', 'Distinct software names', sw_names,
        {'text': f'Across {n(sw_records)} records by name, version, platform and architecture'}, 'Installed software report'),
       ('Mailboxes', 'By recipient type', mbx_total, breakdown(mbx_parts, 'Exchange', inverse(MAILBOX)), 'Mailboxes, Teams and SharePoint report'),
       ('Teams', 'By visibility', teams_total, breakdown(team_parts, 'Teams', inverse(TEAM_VIS)), 'Mailboxes, Teams and SharePoint report'),
       ('SharePoint and OneDrive sites', 'By site kind', sites_total,
        breakdown(site_parts, 'SharePoint isPersonalSite', {'SharePoint sites': 'false', 'OneDrive accounts': 'true'}),
        'Mailboxes, Teams and SharePoint report')]
env_rows = [{'obj': {'text': o, 'sub': sub}, 'count': n(c), 'parts': parts, 'report': {'text': rep}} for o, sub, c, parts, rep in ENV]
os_note = ('Operating systems group the reported names: ' + ', '.join(f'{k} ({", ".join(v)})' for k, v in merged) + '. ') if merged else ''

# ---------------------------------------------------------------- high-impact users and their devices
HU = sorted(R.rows('high_impact_users'), key=lambda u: (str(u.get('displayName') or '').lower(), u['id']))
HD_ALL = sorted(R.rows('high_impact_devices'), key=lambda d: (str(d.get('displayName') or '').lower(), d['id']))
for rows_, allowed, what in ((HU, USER_REASONS, 'high_impact_users'), (HD_ALL, DEVICE_REASONS, 'high_impact_devices')):
    for rec in rows_:
        if not reasons(rec) or any(t not in allowed for t in reasons(rec)):
            sys.exit(f'{what} holds {rec["id"]} with reasons {reasons(rec)}: label every reason in USER_REASONS or DEVICE_REASONS')
USERS = {u['id']: u for u in HU}
hu_total = fact('highImpact.users', len(HU), 'high_impact_users')
hu_reason = fact('highImpact.usersByReason', {IMPACT_REASON[t]: sum(1 for u in HU if t in reasons(u)) for t in USER_REASONS}, 'high_impact_users')
hu_state = fact('highImpact.usersByState', {'Enabled': sum(1 for u in HU if u.get('accountEnabled') is True),
                                            'Disabled': sum(1 for u in HU if u.get('accountEnabled') is False)}, 'high_impact_users')

# Counts and the table cover active corporate devices, the Devices report's scope; the other records are counted by scope.
HD = [d for d in HD_ALL if d.get('ownershipClassification') == 'Corporate' and d.get('isInactive') is False]


def scope_of(d):
    own = d.get('ownershipClassification') or 'No ownership on record'
    act = {True: 'inactive', False: 'active'}.get(d.get('isInactive'), 'no contact on record')
    return f'{own}, {act}'


hd_outside = fact('highImpact.devicesOutsideScope', dict(sorted(Counter(scope_of(d) for d in HD_ALL if d not in HD).items())),
                  'high_impact_devices')
fact('highImpact.deviceRecords', len(HD_ALL), 'high_impact_devices')
hd_outside_total = fact('highImpact.devicesOutsideScopeTotal', sum(hd_outside.values()), 'high_impact_devices')

crit = Counter()  # device id -> software versions on it whose highest Defender CVE rating is Critical
for r in R.rows('critical_software'):
    for dev in sorted({d for d in (r.get('devices[].coreDeviceId') or []) if d}):
        crit[dev] += 1
fact('software.criticalVersions', R.total('critical_software'), 'critical_software')
level = lambda d: d.get('defenderDevice.exposureLevel')
with_crit = [d for d in HD if crit[d['id']]]
with_high = [d for d in HD if level(d) == 'High']
either = sorted((d for d in HD if crit[d['id']] or level(d) == 'High'),
                key=lambda d: (level(d) != 'High', -crit[d['id']], str(d.get('displayName') or '').lower(), d['id']))
hd_total = fact('highImpact.devices', len(HD), 'high_impact_devices')
hd_reason = fact('highImpact.devicesByReason', {IMPACT_REASON[t]: sum(1 for d in HD if t in reasons(d)) for t in DEVICE_REASONS}, 'high_impact_devices')
hd_defender = fact('highImpact.devicesInDefender', sum(1 for d in HD if d.get('defenderDeviceId')), 'high_impact_devices')
hd_crit = fact('highImpact.devicesCriticalCve', len(with_crit), 'high_impact_devices + critical_software')
hd_high = fact('highImpact.devicesExposureHigh', len(with_high), 'high_impact_devices')
hd_either = fact('highImpact.devicesCriticalOrHigh', len(either), 'high_impact_devices + critical_software')
for lv in sorted({level(d) for d in either if level(d) is not None}):
    if lv not in EXPOSURE_LEVEL:
        sys.exit(f'high_impact_devices holds exposure level {lv!r}: add its Defender portal label to EXPOSURE_LEVEL')
shown = either[:DEVICE_ROWS]


def owner_of(d):
    """The high-impact owner a device inherits from, if the collected users hold that owner."""
    return next((USERS[s] for s in (d.get('system.impactSources[].inheritanceSourceId') or []) if s in USERS), None)


def device_cell(d):
    bits = [D(os_family(d['operatingSystem'])) if d.get('operatingSystem') else None,
            IMPACT_REASON['manualAssignment'] if 'manualAssignment' in reasons(d) else None]
    return {'text': D(d.get('displayName') or d['id']), 'sub': ' · '.join(b for b in bits if b)}


def owner_cell(d):
    u = owner_of(d)
    if u:
        return {'text': D(u.get('displayName') or u['id']), 'sub': ', '.join(IMPACT_REASON[t] for t in USER_REASONS if t in reasons(u))}
    return {'text': D(d['owner']) if d.get('owner') else 'No owner on record'}


def exposure_cell(d):
    lv = level(d)
    return R.state(EXPOSURE_LEVEL[lv], lv, 'Defender') if lv is not None else {'text': 'Not reported'}


fact('highImpact.deviceTable', [{'device': d.get('displayName'), 'owner': (owner_of(d) or {}).get('displayName') or d.get('owner'),
                                 'exposureLevel': level(d), 'criticalVersions': crit[d['id']]} for d in shown],
     'high_impact_devices + high_impact_users + critical_software')
hi_device_rows = [{'device': device_cell(d), 'owner': owner_cell(d), 'exposure': exposure_cell(d), 'crit': n(crit[d['id']])} for d in shown]

# ---------------------------------------------------------------- sections
R.hero(f'Findings, Microsoft Secure Score and its recommended actions, high-impact users and devices, and object counts for the {R.tenant_raw} '
       f'Microsoft 365 tenant, from data collected on {R.as_of}.',
       scope=[('Enabled members', n(enabled), f'Of {n(members)} member accounts'),
              ('Guests', n(guests)),
              ('Active corporate devices', n(activity['Active']), f'Of {n(own["Corporate"])} corporate devices'),
              ('Apps from other publishers', n(other_pub), f'Of {n(sps)} service principals'),
              ('Mailboxes', n(mbx_total)),
              ('Teams', n(teams_total)),
              ('SharePoint sites', n(sites['SharePoint sites']), f'Plus {n(sites["OneDrive accounts"])} OneDrive accounts')])
overall = now.get('Overall')
R.kpis([
    {'kicker': 'Microsoft Secure Score', 'value': pct1(overall['percent']) if overall else None,
     'foot': f'{num(overall["points"])} of {num(overall["max"])} points on {taken}.' if overall else None},
    {'kicker': 'Open findings', 'value': n(open_total),
     'foot': f'Accepted: {n(acc_total)}. Largest area: {lead[0]}, {n(area_facts[lead[0]]["open"])} open '
             f'({pct1(area_facts[lead[0]]["share"])}).'},
    {'kicker': 'High-impact users', 'value': n(hu_total),
     'foot': ' '.join(f'{k}: {n(v)}.' for k, v in hu_reason.items())},
    {'kicker': 'High-impact active corporate devices with a Critical CVE or exposure level High', 'value': n(hd_either), 'unit': f' of {n(hd_total)}',
     'foot': f'Critical CVE: {n(hd_crit)}. Exposure level High: {n(hd_high)}.'},
    {'kicker': 'Conditional Access policies on', 'value': n(ca['On']), 'unit': f' of {n(ca_total)}',
     'foot': f'Report-only: {n(ca["Report-only"])}. Off: {n(ca["Off"])}.'},
])
R.add({'type': 'panels', 'kicker': 'Findings', 'title': 'Findings by area', 'cols': 1, 'panels': [{
    'kicker': 'Open and accepted findings by area',
    'cols': [{'key': 'area', 'label': 'Area'}, {'key': 'open', 'label': 'Open', 'n': True}, {'key': 'acc', 'label': 'Accepted', 'n': True},
             {'key': 'share', 'label': 'Share of open', 'n': True}, {'key': 'top', 'label': 'Check with the most open findings'},
             {'key': 'report', 'label': 'Covered in'}],
    'rows': area_rows,
    'note': f'{STATUS_NOTE} Share of open: the area’s part of all open findings.'}]}, 'findings-by-area')
R.add({'type': 'panels', 'kicker': 'Findings', 'title': 'Checks with the most open findings', 'cols': 1, 'panels': [{
    'kicker': f'The {n(len(top))} checks with the most open findings',
    'cols': [{'key': 'check', 'label': 'Check and what it checks'}, {'key': 'asset', 'label': 'Asset type'},
             {'key': 'open', 'label': 'Open', 'n': True}, {'key': 'share', 'label': 'Share of open', 'n': True}],
    'rows': [{'check': {'text': D(DEFS[f]['displayName']), 'sub': D(DEFS[f]['description'])}, 'asset': {'text': ASSET[DEFS[f]['type']]},
              'open': n(o_check[f]), 'share': pct1(share(o_check[f]))} for f in top],
    'note': (f'These {n(len(top))} checks hold {n(top_open)} of {n(open_total)} open findings, {pct1(top_share)}. ' if top else '') +
            f'{n(len(ranked))} of {n(len(DEFS))} checks have open findings. Equal counts follow the area order, then the finding registry’s order.'}]},
      'top-checks')
SCORE_COLS = [{'key': 'measure', 'label': 'Measure'}, {'key': 'points', 'label': 'Points', 'n': True},
              {'key': 'max', 'label': 'Maximum', 'n': True}, {'key': 'percent', 'label': 'Percent', 'n': True}]
R.add({'type': 'panels', 'kicker': 'Microsoft Secure Score', 'title': 'Secure Score by category', 'cols': 2, 'panels': [
    {'kicker': f'Microsoft Secure Score on {taken}' if taken else 'Microsoft Secure Score', 'cols': SCORE_COLS, 'rows': score_rows,
     'note': ('As Microsoft reports it, from the snapshot in the collected data. The maximum depends on the tenant’s licenses and services.'
              if now else 'The collected data holds no Microsoft Secure Score snapshot.')},
    {'kicker': 'Recommended actions below their maximum points, by category',
     'cols': [{'key': 'cat', 'label': 'Microsoft category'}, {'key': 'below', 'label': 'Below maximum', 'n': True},
              {'key': 'scored', 'label': 'Actions scored', 'n': True}],
     'rows': control_rows,
     'note': 'Recommended actions in the tenant’s latest Microsoft Secure Score. Deprecated actions are left out.'}]}, 'secure-score')
R.add({'type': 'panels', 'kicker': 'Microsoft Secure Score', 'title': 'Recommended actions by category', 'cols': 1,
       'panels': [action_panel(c) for c in cats if by_cat.get(c)] or [{
           'kicker': 'Recommended actions below their maximum points', 'cols': [{'key': 'none', 'label': 'Recommended action'}],
           'rows': [], 'note': 'Every recommended action in the tenant’s latest Microsoft Secure Score earns its maximum points.'}]},
      'secure-score-actions')
R.add({'type': 'panels', 'kicker': 'High impact', 'title': 'High-impact users and devices', 'cols': 2, 'panels': [
    {'kicker': 'High-impact users by reason',
     'cols': [{'key': 'reason', 'label': 'Reason'}, {'key': 'count', 'label': 'Users', 'n': True}],
     'rows': [{'reason': {'text': k}, 'count': n(v)} for k, v in hu_reason.items()] +
             [{'reason': {'text': 'All high-impact users', 'sub': f'Enabled accounts: {n(hu_state["Enabled"])}. Disabled: {n(hu_state["Disabled"])}.'},
               'count': n(hu_total)}],
     'note': 'A user can have more than one reason. Privileged directory role: a direct member of a role Microsoft marks privileged. '
             'Org chart: the top-level user set in the tenant’s impact settings, or a direct report. Marked by a technician: set by hand '
             'on the user. The privileged role and org chart rules run only where the tenant’s impact settings turn them on.'},
    {'kicker': 'High-impact devices',
     'cols': [{'key': 'measure', 'label': 'Devices'}, {'key': 'count', 'label': 'Count', 'n': True}],
     'rows': [{'measure': {'text': 'High-impact active corporate devices'}, 'count': n(hd_total)}] +
             [{'measure': {'text': f'Reason: {k}'}, 'count': n(v)} for k, v in hd_reason.items()] +
             [{'measure': {'text': 'With a Microsoft Defender for Endpoint record'}, 'count': n(hd_defender)},
              {'measure': {'text': 'With a Critical CVE'}, 'count': n(hd_crit)},
              {'measure': {'text': 'With exposure level High'}, 'count': n(hd_high)},
              {'measure': {'text': 'With a Critical CVE or exposure level High'}, 'count': n(hd_either)},
              {'measure': {'text': 'High-impact device records outside that scope',
                           'sub': ' '.join(f'{k}: {n(v)}.' for k, v in hd_outside.items()) or None},
               'count': n(hd_outside_total)}],
     'note': 'High-impact devices: the devices of high-impact users, and devices a technician marked. Active corporate: corporate '
             'ownership and contact from any source within 30 days of collection, the scope of the Devices report. Critical CVE: a software version '
             'on the device whose highest CVE rating from Defender Vulnerability Management is Critical. Exposure level: as Microsoft '
             'Defender for Endpoint rates the device.'}]}, 'high-impact')
R.add({'type': 'panels', 'kicker': 'High impact', 'title': f'High-impact active corporate devices with a Critical CVE or exposure level High: {n(hd_either)}',
       'cols': 1, 'panels': [{
           'kicker': f'Devices listed: {n(len(shown))} of {n(hd_either)}',
           'cols': [{'key': 'device', 'label': 'Device'}, {'key': 'owner', 'label': 'Owner'},
                    {'key': 'exposure', 'label': 'Exposure level'}, {'key': 'crit', 'label': 'Software versions with a Critical CVE', 'n': True}],
           'rows': hi_device_rows,
           'note': (f'Exposure level High first, then the most software versions with a Critical CVE, then device name; at most '
                    f'{n(DEVICE_ROWS)} rows. Beneath the device: its operating system. Beneath the owner: why the owner is high impact. Exposure level: the Defender portal label, with the '
                    f'value Defender’s API reports beneath it.'
                    if shown else 'No high-impact active corporate device in the collected data has a Critical CVE or exposure level High.')}]},
      'high-impact-devices')
R.add({'type': 'panels', 'kicker': 'Environment', 'title': 'Objects in the tenant', 'cols': 1, 'panels': [{
    'kicker': 'Counts by object type',
    'cols': [{'key': 'obj', 'label': 'Object'}, {'key': 'count', 'label': 'Count', 'n': True}, {'key': 'parts', 'label': 'Breakdown'},
             {'key': 'report', 'label': 'Covered in'}],
    'rows': env_rows,
    'note': esc('Beneath a breakdown: the value each label stands for in its source, in the same order. '
                'Active corporate device: contact from Entra, Intune, Defender or Autopilot in the 30 days before collection; '
                'a device with no contact date on record counts as active. ' + os_note +
                'Apps from other publishers: service principals whose publisher tenant is neither this organization’s nor one of '
                'Microsoft’s. Installed software comes from the Microsoft Defender for Endpoint software inventory. '
                'OneDrive accounts are the sites Microsoft marks as personal.')}]}, 'objects')
R.footer(f'Read-only collection on {R.as_of}. Every value comes from a fixed query of one collection run: counts grouped by one '
         f'field, finding counts by status and check, the latest Microsoft Secure Score snapshot and its recommended actions below '
         f'their maximum points, and the users and devices the '
         f'product marks high impact with the software versions Defender rates Critical. The same queries run for every tenant.',
         'Open: Needs Review or Flagged. Accepted: a reviewer set the finding to Accepted. Share of open: the part of all open '
         'findings. Secure Score percent: points earned of the tenant’s maximum, as Microsoft reports it. High impact: users the '
         'product marks for a privileged directory role, the configured org chart or a technician’s marking; their devices; and '
         'devices a technician marked.',
         'Findings with status Action Taken, Stale or Resolved, and matches a check holds as Detected during its observation '
         'window. Secure Score recommended actions that Microsoft deprecated or left out of the tenant’s latest score. Software on devices '
         'not onboarded to Microsoft Defender for Endpoint.')
R.write()
