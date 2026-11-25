"""Entra apps report recipe, v0.4.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/entra_apps_deep_dive/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

<run-dir>/run.json names the tenant and date; <run-dir>/inputs/<id>.json holds the response to each query in
queries.json, saved exactly as returned. The title band shows the working set: the service principals not published by
Microsoft, by publisher. The report opens with the Entra app findings and Microsoft Secure Score, then shows the service
principals by publisher, directory roles and application permissions held by apps, credentials, creation dates, consent
and sign-in activity. Every finding check has a data view, and a view with nothing in it still shows its zero.

Single ingest (2026-10-07): every date is one Microsoft returns on the object (createdDateTime on the service
principal and on each app role assignment, credential start and end dates) or in its sign-in activity report
(lastSignInDateTime), so a prospect's first pull gives the same report. lastConsentDateTime is not read: the Collector
takes it from audit log consent events in the 30 days before a run, and Entra keeps 7 days of audit log without P1 or P2.

Microsoft-published apps (appOwnerOrganizationId in MICROSOFT_TENANTS) are counted in the estate and left out of
every table. Application permissions come from each API's list of assigned apps (appRoleAssignedTo), because an
app's own appRoleAssignments list stops at 20 and its stored permissionValue labels are unreliable; names come from
the API's appRoles by appRoleId. Application permissions carry no privilege marking (how to mark
them is not decided), and the product's per-permission risk rating is not used. Service principals carry no high-impact marking in
the data, so none is shown. Facts only, no vendor branding, and the same inputs always produce the same bytes.

v0.3.0 (2026-10-14): apps that can read company content, from the application
permissions and delegated grants they hold on Microsoft Graph, Exchange Online and SharePoint Online, by content area and
by how the permission was granted. CONTENT lists the permission names that count.

v0.4.0 (2026-11-03): the app access report's app-to-data diagram opens the report, after the headline numbers. It
comes from app_reach.py, which the app access recipe also uses, built from this report's own queries.
"""
import datetime as dt, pathlib, re, sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import Report, esc, n, num, width  # noqa: E402
from app_reach import HOW, LABEL, OWN_FOLDER, SHOW, SIGN_IN, area as reach_area, diagram, diagram_rows, tally  # noqa: E402

R = Report(__file__, 'entra-apps-deep-dive', '0.4.0', 'Entra apps report')
D, fact = R.D, R.fact
TENANT_ID = R.run['tenantId']

# ---------------------------------------------------------------- knowledge tables and rules
# Microsoft tenants that publish apps, from references/app-classification-convention.md (validated on Microsoft Learn
# and live data). queries.json repeats the list in its filters; the build checks the two agree.
MICROSOFT_TENANTS = ['f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47',
                     'cdc5aeea-15c5-4db6-b079-fcadd2505dc2', '33e01921-4d64-4f8c-a055-5bdaffd5e33d',
                     '0d933fb8-3f65-4722-9430-08d60fc88af4', '975f013f-7f24-47e8-a7d3-abc4752bf346',
                     '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8']
# Microsoft Graph servicePrincipalType values in Microsoft's order, with the words Microsoft's servicePrincipal reference
# uses for each (ServiceIdentity: an agent identity; SocialIdp: for internal use).
TYPE_LABEL = {'Application': 'Application', 'ManagedIdentity': 'Managed identity', 'Legacy': 'Legacy',
              'ServiceIdentity': 'Agent identity', 'SocialIdp': 'Social identity provider'}
SP_TYPES = list(TYPE_LABEL)
GROUPS = [('own', 'This organization'), ('other', 'Other publishers'), ('none', 'No publisher tenant')]
SAML = 'CN=Microsoft Azure Federated SSO Certificate'          # the name Entra gives SAML signing credentials
CREDS = [('secret', 'Client secrets', 'clientSecretStatus'), ('cert', 'Client certificates', 'clientCertificateStatus'),
         ('saml', 'SAML signing certificates', 'samlCredentialStatus')]
ONE = {'secret': 'Client secret', 'cert': 'Client certificate', 'saml': 'SAML signing certificate'}
RATING = {'Expiring': 'Expiring within 30 days', 'Expired': 'Expired'}   # the collector's ratings this report lists, in table order
REC = [('0 to 7 days', 0, 7), ('8 to 30 days', 8, 30), ('31 to 45 days', 31, 45), ('More than 45 days', 46, 10 ** 6)]
AGE = [('0 to 7 days', 0, 7), ('8 to 30 days', 8, 30), ('31 to 365 days', 31, 365), ('More than 365 days', 366, 10 ** 6)]
NEVER = 'Never signed in'                                         # a sign-in field with no date (2026-10-07)
WINDOW = 30                                                       # days before collection (constant in check_facts)
LONG_LIVED_YEARS = fact('rules.longLivedYears', 3, 'recipe rule: a current credential valid for more than this many years')
STORED_MAX = fact('limits.ownListMax', 20, 'collector limit: an app’s own appRoleAssignments list stops at 20')
DEFAULT_ROLE = '00000000-0000-0000-0000-000000000000'             # Microsoft's default app role, named Default Access
# Finding checks whose data the report names: the knowledge for lastSignInDateTime, directoryRoles[].isPrivileged and
# lastConsentDateTime says which field each one reads.
NOT_SIGNED_IN = '2f377c21-208f-48d7-8ba4-2eaba96993b0'
PRIVILEGED_ROLE = '4aed53f7-b2bc-4c23-b961-8e3b276d386b'
RECENT_CONSENT = '07fbbf07-8cbf-4fc0-896d-cd0d21f61773'

# Table order for directory roles, from the Identity report: Global Administrator first.
ROLE_ORDER = ['Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
              'Security Administrator', 'Conditional Access Administrator', 'Application Administrator',
              'Cloud Application Administrator', 'Hybrid Identity Administrator', 'Authentication Administrator',
              'User Administrator', 'Intune Administrator', 'Helpdesk Administrator', 'Password Administrator',
              'Cloud Device Administrator', 'Domain Name Administrator', 'Security Operator', 'Global Reader',
              'Security Reader']

for q in R.spec['queries']:                                       # every query names the same Microsoft tenants
    listed = [v for f in q.get('filters', []) if f['field'] == 'appOwnerOrganizationId'
              for v in (f['value'] if f['operator'] == 'in' else [f['value']] if f['operator'] == 'ne' else [])]
    if listed and sorted(listed) != sorted(MICROSOFT_TENANTS):
        sys.exit(f'{q["id"]} and MICROSOFT_TENANTS list different Microsoft tenants')


# ---------------------------------------------------------------- company content (2026-10-14)
# Permission names that read company content, on Microsoft's own APIs, by content area. Matching ignores case; a write
# permission includes read. Files.ReadWrite.AppFolder reaches only the app's own folder and is left out.
CONTENT_APIS = ('Microsoft Graph', 'Office 365 Exchange Online', 'Office 365 SharePoint Online')
CONTENT = [('Mail', r'Mail\.Read.*|full_access_as_app|EWS\.AccessAsUser\.All|(IMAP|POP)\.AccessAs(User\.All|App)'),
           ('Files and sites', r'Files\.Read.*|Files\.SelectedOperations\..*|Sites\.(Read|ReadWrite|Manage|FullControl)\.All|'
                               r'Sites\.Selected|AllSites\..*|MyFiles\..*'),
           ('Chats and channel messages', r'Chat\.Read.*|ChatMessage\.Read.*|ChannelMessage\.Read.*'),
           ('Calendars', r'Calendars\.Read.*'),
           ('Contacts', r'Contacts\.Read.*'),
           ('Notes', r'Notes\.Read.*'),
           ('Meeting transcripts and recordings', r'OnlineMeeting(Transcript|Recording|Artifact)\.Read.*')]
CONTENT_OUT = re.compile(r'.*\.AppFolder', re.I)


def content_area(api, perm):
    """The content area a permission reaches, or None."""
    if api not in CONTENT_APIS or CONTENT_OUT.fullmatch(perm):
        return None
    return next((area for area, rx in CONTENT if re.fullmatch(rx, perm, re.I)), None)


# ---------------------------------------------------------------- helpers
def ts(s):
    """An ISO timestamp as an aware UTC datetime; tolerates Z, no zone and 0 to 7 fractional digits."""
    if not s:
        return None
    m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$', str(s).strip())
    if not m:
        sys.exit(f'unreadable timestamp {s!r}')
    base, frac, zone = m.groups()
    zone = '+00:00' if zone in (None, 'Z') else zone
    return dt.datetime.fromisoformat(f'{base}.{(frac or "")[:6].ljust(6, "0")}{zone}')


def plus_years(d, k):
    try:
        return d.replace(year=d.year + k)
    except ValueError:                                            # 29 February
        return d.replace(year=d.year + k, day=28)


def days_before(s):
    """Whole days from a timestamp to the end of the collection day; None when there is no date."""
    age = R.age(ts(s))
    return None if age is None else max(age, 0)


def bucket(age, edges, none):
    return none if age is None else next(label for label, lo, hi in edges if lo <= age <= hi)


def group(a):
    o = a.get('appOwnerOrganizationId')
    return 'own' if o == TENANT_ID else ('none' if o is None else 'other')


def type_label(t):
    return TYPE_LABEL.get(t) or D(t)


def publisher(a):
    g = group(a)
    if g == 'own':
        return 'This organization'
    if g == 'none':
        return f'No publisher tenant · {type_label(a["servicePrincipalType"])}'
    vp = a.get('verifiedPublisher.displayName')
    return f'Verified publisher {D(vp)}' if vp else 'No verified publisher'


def app_cell(a):
    return {'text': D(a['displayName']), 'sub': publisher(a)}


def by_name(a):
    return (a['displayName'].lower(), a['id'])


def signed_in(a, f='lastSignInDateTime'):
    return R.day(ts(a.get(f)), none=NEVER)


def created(a):
    return R.day(ts(a.get('createdDateTime')), none='No creation date')


def enabled(a):
    return 'Yes' if a.get('accountEnabled') else 'No'


def bars(counts, of, quiet=()):
    return [{'label': esc(k), 'value': n(v), 'pct': width(v, of),
             'color': 'var(--neutral-mark)' if k in quiet else 'var(--series-1)'} for k, v in counts.items()]


def check_name(fid):
    d = next((d for d in R.IN['definitions']['definitions'] if d['id'] == fid), None)
    return esc(D(d['displayName'])) if d else None


# ---------------------------------------------------------------- the estate
total = fact('estate.servicePrincipals', R.total('sp_by_type'), 'sp_by_type')
types = R.buckets('sp_by_type')
type_order = [t for t in SP_TYPES if t in types] + [t for t, _ in sorted(types.items(), key=lambda kv: (-kv[1], kv[0])) if t not in SP_TYPES]
by_type = fact('estate.byType', {type_label(t): types[t] for t in type_order}, 'sp_by_type')
for t in type_order:
    D(t)
microsoft = fact('estate.microsoft', R.total('sp_microsoft_by_tenant'), 'sp_microsoft_by_tenant')
fact('estate.microsoftByTenant', {t: R.buckets('sp_microsoft_by_tenant').get(t, 0) for t in MICROSOFT_TENANTS}, 'sp_microsoft_by_tenant')

A = sorted(R.rows('apps'), key=by_name)
APP = {a['id']: a for a in A}
if any(a.get('appOwnerOrganizationId') in MICROSOFT_TENANTS for a in A):
    sys.exit('apps holds a Microsoft-published service principal; check the filters')
if microsoft + len(A) != total:
    sys.exit(f'{microsoft} Microsoft-published + {len(A)} others != {total} service principals; run the queries again')
for a in A:
    D(a['displayName'])
nonms = fact('estate.notMicrosoft', len(A), 'apps')
by_group = fact('estate.byPublisher', {label: sum(1 for a in A if group(a) == g) for g, label in GROUPS}, 'apps')
# Rows for the table that splits apps by publisher: this organization, other publishers, then no publisher tenant by type.
SEGMENTS = [(label, lambda a, g=g: group(a) == g) for g, label in GROUPS[:2]] + \
           [(f'No publisher tenant · {type_label(t)}', lambda a, t=t: group(a) == 'none' and a['servicePrincipalType'] == t)
            for t in sorted({a['servicePrincipalType'] for a in A if group(a) == 'none'}, key=lambda t: (SP_TYPES.index(t) if t in SP_TYPES else 99, t))]
status_rows = fact('estate.statusByPublisher', {label: {'apps': sum(1 for a in A if test(a)),
                                                        'enabled': sum(1 for a in A if test(a) and a.get('accountEnabled') is True),
                                                        'disabled': sum(1 for a in A if test(a) and a.get('accountEnabled') is False),
                                                        'disabledByMicrosoft': sum(1 for a in A if test(a) and a.get('disabledByMicrosoftStatus')
                                                                                   not in (None, 'NotDisabled'))}
                                                for label, test in SEGMENTS}, 'apps')
OTHER = [a for a in A if group(a) == 'other']
verified = fact('estate.otherByVerification', {'Verified publisher on record': sum(1 for a in OTHER if a.get('verifiedPublisher.displayName')),
                                               'No verified publisher': sum(1 for a in OTHER if not a.get('verifiedPublisher.displayName'))}, 'apps')
publishers = Counter(a['verifiedPublisher.displayName'] for a in OTHER if a.get('verifiedPublisher.displayName'))
fact('estate.verifiedPublishers', dict(sorted(publishers.items())), 'apps')
publisher_bars = {'Microsoft': microsoft} | by_group

# ---------------------------------------------------------------- directory roles
ms_roles = fact('roles.microsoftPublished', {'apps': R.total('microsoft_with_roles'), 'byRole': R.buckets('microsoft_with_roles')},
                'microsoft_with_roles')
for role in ms_roles['byRole']:
    D(role)


def roles(a):
    return list(zip(a.get('directoryRoles[].displayName') or [], a.get('directoryRoles[].isPrivileged') or []))


def role_rank(a):
    held = [r for r, _ in roles(a)]
    return (not any(p for _, p in roles(a)), min(ROLE_ORDER.index(r) if r in ROLE_ORDER else len(ROLE_ORDER) for r in held),
            -sum(1 for _, p in roles(a) if p), -len(held), by_name(a))


RA = sorted((a for a in A if roles(a)), key=role_rank)
priv_apps = [a for a in RA if any(p for _, p in roles(a))]
ga_apps = [a for a in RA if any(r == 'Global Administrator' for r, _ in roles(a))]
fact('roles.apps', {a['id']: {'app': a['displayName'], 'roles': {r: bool(p) for r, p in roles(a)}} for a in RA}, 'apps')
fact('roles.privilegedApps', len(priv_apps), 'apps')
fact('roles.globalAdministratorApps', len(ga_apps), 'apps')

# ---------------------------------------------------------------- application permissions, from each API's assignments
GRANTS = defaultdict(list)                                        # app id -> [(api, permission, granted)]
for res in sorted(R.rows('api_assignments'), key=lambda r: (r['displayName'].lower(), r['id'])):
    name = {i: (v or d) for i, v, d in zip(res.get('appRoles[].id') or [], res.get('appRoles[].value') or [], res.get('appRoles[].displayName') or [])}
    cols = [res.get(f'appRoleAssignedTo[].{k}') or [] for k in ('principalId', 'principalType', 'appRoleId', 'createdDateTime')]
    if len({len(c) for c in cols}) > 1:
        sys.exit(f'appRoleAssignedTo arrays on {res["displayName"]} differ in length')
    for pid, ptype, role, made in zip(*cols):
        if ptype != 'ServicePrincipal' or pid not in APP:
            continue                                              # users, groups and Microsoft-published apps
        label = name.get(role) or ('Default Access' if role == DEFAULT_ROLE else f'App role {role}')
        GRANTS[pid].append((D(res['displayName']), D(label), made))
for pid in GRANTS:                                                # one row per API and permission name, the earliest grant date
    first = {}
    for api, perm, made in sorted(GRANTS[pid], key=lambda g: (g[0], g[1], g[2] or '9999')):
        first.setdefault((api, perm), made)
    GRANTS[pid] = sorted(((api, perm, made) for (api, perm), made in first.items()), key=lambda g: (g[0].lower(), g[1].lower(), g[0], g[1]))
PA = sorted((APP[p] for p in GRANTS), key=lambda a: (-len(GRANTS[a['id']]), by_name(a)))
grant_total = sum(len(g) for g in GRANTS.values())
over_cap = [a for a in PA if len(GRANTS[a['id']]) > STORED_MAX]
fact('appPermissions.byApp', {a['id']: {'app': a['displayName'], 'permissions': len(GRANTS[a['id']]),
                                        'byApi': dict(sorted(Counter(g[0] for g in GRANTS[a['id']]).items()))} for a in PA}, 'api_assignments + apps')
fact('appPermissions.apps', len(PA), 'api_assignments + apps')
api_count = fact('appPermissions.apis', len({g[0] for gs in GRANTS.values() for g in gs}), 'api_assignments + apps')
fact('appPermissions.grants', grant_total, 'api_assignments + apps')
fact('appPermissions.appsOverOwnListMax', [a['displayName'] for a in over_cap], 'api_assignments + apps')
dates = sorted(g[2] for gs in GRANTS.values() for g in gs if g[2])
by_year = fact('appPermissions.grantedByYear', dict(sorted(Counter(d[:4] for d in dates).items())), 'api_assignments')
undated = fact('appPermissions.undated', grant_total - len(dates), 'api_assignments')


def grant_html(a):
    """One line per API, the API with the most permissions first: <b>API (count)</b>: names."""
    per_api = defaultdict(list)
    for api, perm, _ in GRANTS[a['id']]:
        per_api[api].append(perm)
    return '<br>'.join(f'<b>{esc(api)} ({n(len(p))})</b>: {esc(", ".join(p))}'
                       for api, p in sorted(per_api.items(), key=lambda kv: (-len(kv[1]), kv[0].lower())))


def granted(gs, last=False):
    ds = sorted(g[2] for g in gs if g[2])
    return R.day(ts(ds[-1 if last else 0]) if ds else None, none='No grant date')


# Application permissions granted in the window: Microsoft's createdDateTime on the app role assignment.
RECENT = {pid: [g for g in gs if g[2] and days_before(g[2]) <= WINDOW] for pid, gs in GRANTS.items()}
RECENT = {pid: gs for pid, gs in RECENT.items() if gs}
RG = sorted((APP[p] for p in RECENT), key=lambda a: (-max(ts(g[2]) for g in RECENT[a['id']]).timestamp(), by_name(a)))
fact('consent.applicationGrantsInWindow', {a['id']: {'app': a['displayName'], 'permissions': len(RECENT[a['id']]),
                                                     'held': len(GRANTS[a['id']]), 'first': granted(RECENT[a['id']]),
                                                     'last': granted(RECENT[a['id']], last=True)} for a in RG}, 'api_assignments + apps')

# ---------------------------------------------------------------- delegated permissions and consent
DG = {}
for r in R.rows('delegated_grants'):
    cols = [r.get(f'oauth2PermissionGrants[].{k}') or [] for k in ('resourceDisplayName', 'permissionValue', 'consentType', 'principalId')]
    if len({len(c) for c in cols}) > 1:
        sys.exit(f'oauth2PermissionGrants arrays on {r["displayName"]} differ in length')
    if r['id'] in APP:
        DG[r['id']] = sorted({(D(res), D(p), D(c), u) for res, p, c, u in zip(*cols)}, key=lambda g: (g[0].lower(), g[1].lower(), g[2], g[3] or ''))
USERS = {u['id']: u for u in R.rows('users')}


def user_name(uid):
    u = USERS.get(uid)
    if not u:
        return f'Not in collected users ({uid})'
    return D(u['displayName']) + (' (Guest)' if u.get('userType') == 'Guest' else '')


admin_apps = [APP[i] for i in DG if any(g[2] == 'AllPrincipals' for g in DG[i])]
user_apps = sorted((APP[i] for i in DG if any(g[2] == 'Principal' for g in DG[i])), key=by_name)
consenters = {a['id']: sorted({g[3] for g in DG[a['id']] if g[2] == 'Principal' and g[3]}, key=lambda u: (user_name(u).lower(), u)) for a in user_apps}
by_user = defaultdict(list)
for a in user_apps:
    for u in consenters[a['id']]:
        by_user[u].append(a)
user_rows = sorted(by_user.items(), key=lambda kv: (-len(kv[1]), user_name(kv[0]).lower(), kv[0]))
consent_types = fact('consent.byType', {'Application permissions': len(PA),
                                        'Delegated, admin consent for all users': len(admin_apps),
                                        'Delegated, user consent': len(user_apps)}, 'api_assignments + delegated_grants')
fact('consent.adminAndUser', sum(1 for a in user_apps if a in admin_apps), 'delegated_grants')
fact('consent.delegatedApps', len(DG), 'delegated_grants')
fact('consent.userConsentApps', {a['id']: {'app': a['displayName'], 'users': [user_name(u) for u in consenters[a['id']]],
                                           'permissions': len({g[1] for g in DG[a['id']] if g[2] == 'Principal'})} for a in user_apps}, 'delegated_grants + users')
fact('consent.byUser', {u: {'user': user_name(u), 'apps': len(v)} for u, v in user_rows}, 'delegated_grants + users')

# ---------------------------------------------------------------- disabled apps that hold permissions or roles
disabled = sorted((a for a in A if a.get('accountEnabled') is False and (a['id'] in GRANTS or a['id'] in DG or roles(a))), key=by_name)
fact('disabled.holdingAccess', {a['id']: {'app': a['displayName'], 'application': len(GRANTS.get(a['id'], [])),
                                          'delegated': len({g[1] for g in DG.get(a['id'], [])})} for a in disabled}, 'apps + api_assignments + delegated_grants')

# ---------------------------------------------------------------- apps that can read company content
AREAS = [area for area, _ in CONTENT]
GRANT_KINDS = ['Application permissions', 'Delegated, admin consent for all users', 'Delegated, user consent']
CONTENT_APPS = {}
for a in A:
    kinds = {
        GRANT_KINDS[0]: sorted({(api, perm) for api, perm, _ in GRANTS.get(a['id'], []) if content_area(api, perm)}),
        GRANT_KINDS[1]: sorted({(res, perm) for res, perm, ct, _ in DG.get(a['id'], []) if ct == 'AllPrincipals' and content_area(res, perm)}),
        GRANT_KINDS[2]: sorted({(res, perm) for res, perm, ct, _ in DG.get(a['id'], []) if ct == 'Principal' and content_area(res, perm)})}
    if any(kinds.values()):
        areas = {content_area(api, perm) for v in kinds.values() for api, perm in v}
        users = sorted({u for res, perm, ct, u in DG.get(a['id'], []) if ct == 'Principal' and u and content_area(res, perm)})
        CONTENT_APPS[a['id']] = {'kinds': kinds, 'areas': [x for x in AREAS if x in areas], 'users': users}
CA_ = sorted((APP[i] for i in CONTENT_APPS), key=lambda a: (tuple(not CONTENT_APPS[a['id']]['kinds'][k] for k in GRANT_KINDS),
                                                           -len(CONTENT_APPS[a['id']]['areas']), by_name(a)))
fact('content.apps', {a['id']: {'app': a['displayName'], 'areas': CONTENT_APPS[a['id']]['areas'], 'users': len(CONTENT_APPS[a['id']]['users']),
                                **{k: [f'{api}: {perm}' for api, perm in v] for k, v in CONTENT_APPS[a['id']]['kinds'].items()}}
                      for a in CA_}, 'api_assignments + delegated_grants + apps')
content_by_area = fact('content.byArea', {x: sum(1 for c in CONTENT_APPS.values() if x in c['areas']) for x in AREAS}, 'api_assignments + delegated_grants')
content_by_kind = fact('content.byGrant', {k: sum(1 for c in CONTENT_APPS.values() if c['kinds'][k]) for k in GRANT_KINDS},
                       'api_assignments + delegated_grants')


# ---------------------------------------------------------------- app-to-data diagram (app_reach.py; 2026-11-03)
# The app access report's diagram from this report's inputs: application permissions from each API's assigned apps, with
# Microsoft's label for the app role, and delegated grants other than sign-in scopes and the app's own folder.
HOLD = defaultdict(lambda: defaultdict(set))                     # app id -> how -> {(area, api, permission, label)}
for res in R.rows('api_assignments'):
    role_names = {i: (v, d) for i, v, d in zip(res.get('appRoles[].id') or [], res.get('appRoles[].value') or [],
                                               res.get('appRoles[].displayName') or [])}
    for pid, ptype, role in zip(*(res.get(f'appRoleAssignedTo[].{k}') or [] for k in ('principalId', 'principalType', 'appRoleId'))):
        value, label = role_names.get(role, (None, None))
        if ptype == 'ServicePrincipal' and pid in APP and value:
            HOLD[pid]['application'].add((reach_area(res['displayName'], value), res['displayName'], value, label or value))
for r in R.rows('delegated_grants'):
    if r['id'] in APP:
        for res, p, ct in zip(*(r.get(f'oauth2PermissionGrants[].{k}') or [] for k in ('resourceDisplayName', 'permissionValue', 'consentType'))):
            if p and p not in SIGN_IN and p != OWN_FOLDER:
                HOLD[r['id']]['admin' if ct == 'AllPrincipals' else 'user'].add((reach_area(res, p), res, p, p))
REACH = sorted((i for i in HOLD if any(HOLD[i].values())), key=lambda i: (APP[i]['displayName'].casefold(), i))
REACH_NAME = {i: APP[i]['displayName'] for i in REACH}
reach_cell, reach_apps, reach_how = tally(HOLD, REACH)
fact('reach.apps', len(REACH), 'api_assignments + delegated_grants')
fact('reach.byGrant', {HOW[h]: len(v) for h, v in reach_how.items()}, 'api_assignments + delegated_grants')
fact('reach.areas', {LABEL[ar]: {'apps': len(reach_apps[ar]), **{HOW[h]: len(reach_cell[ar][h]['apps']) for h in HOW}} for ar in SHOW},
     'api_assignments + delegated_grants')
REACH_ROWS = diagram_rows(HOLD, REACH, REACH_NAME, lambda i: (publisher(APP[i]), enabled(APP[i]), signed_in(APP[i])))
fact('reach.diagramRows', [{'app': REACH_NAME[ids[0]], 'servicePrincipals': len(ids)} for ids in REACH_ROWS], 'api_assignments + delegated_grants')


def reach_sub(ids):
    a = APP[ids[0]]
    return ' · '.join([publisher(a)] + (['Disabled'] if a.get('accountEnabled') is False else []) +
                      [f'Last sign-in: {signed_in(a)}' if a.get('lastSignInDateTime') else NEVER])


# ---------------------------------------------------------------- credentials
def credentials(a):
    """Every credential on the service principal and its app registration: (kind, where, start, end)."""
    out = []
    for prefix, where in (('', 'Service principal'), ('appRegistration.', 'App registration')):
        for field, secret in (('passwordCredentials', True), ('keyCredentials', False)):
            cols = [a.get(f'{prefix}{field}[].{k}') or [] for k in ('displayName', 'startDateTime', 'endDateTime')]
            if len({len(c) for c in cols}) > 1:
                sys.exit(f'{prefix}{field} arrays on {a["displayName"]} differ in length')
            for name, start, end in zip(*cols):
                if name == SAML and not secret:
                    continue                                      # the key pair of a SAML certificate; its password entry counts it
                kind = 'saml' if name == SAML else ('secret' if secret else 'cert')
                out.append((kind, where, ts(start), ts(end)))
    return out


MANAGED = D('Managed by Microsoft')                               # the collector's rating on managed identities' certificates
managed = fact('credentials.managedByMicrosoft', sum(1 for a in A if a.get('clientCertificateStatus.status') == MANAGED), 'apps')
LONG = []
for a in A:
    if a['servicePrincipalType'] == 'ManagedIdentity':
        continue                                                  # Azure issues and rotates these
    for kind, where, start, end in credentials(a):
        if start and end and end > R.AS_OF and end.date() > plus_years(start.date(), LONG_LIVED_YEARS):
            LONG.append((a, kind, where, start, end))
LONG.sort(key=lambda x: ([k for k, _, _ in CREDS].index(x[1]), -x[4].timestamp(), by_name(x[0]), x[2]))
fact('credentials.longLived', [{'app': x[0]['displayName'], 'kind': x[1], 'where': x[2], 'start': R.day(x[3]), 'end': R.day(x[4])} for x in LONG],
     'apps')
fact('credentials.longLivedApps', {kind: len({x[0]['id'] for x in LONG if x[1] == kind}) for kind, _, _ in CREDS}, 'apps')
EXP = []
for kind, label, f in CREDS:
    for a in A:
        if a.get(f'{f}.status') in RATING:
            EXP.append((a, kind, f, a[f'{f}.status'], ts(a.get(f'{f}.expiresOn'))))
EXP.sort(key=lambda x: ([k for k, _, _ in CREDS].index(x[1]), list(RATING).index(x[3]), by_name(x[0])))
exp_counts = fact('credentials.byKindAndRating', {kind: {r: sum(1 for x in EXP if x[1] == kind and x[3] == r) for r in RATING}
                                                  for kind, _, _ in CREDS}, 'apps')
fact('credentials.expiredOrExpiring', [{'app': x[0]['displayName'], 'kind': x[1], 'rating': x[3], 'latestEnd': R.day(x[4], none='No end date')}
                                       for x in EXP], 'apps')
expired_apps = sorted({x[0]['id'] for x in EXP if x[3] == 'Expired'})
fact('credentials.appsWithExpired', len(expired_apps), 'apps')
expiring_apps = fact('credentials.appsWithExpiring', len({x[0]['id'] for x in EXP if x[3] == 'Expiring'}), 'apps')

# ---------------------------------------------------------------- creation dates
AGES = {a['id']: days_before(a.get('createdDateTime')) for a in A}
no_date = sum(1 for a in A if AGES[a['id']] is None)
by_age = fact('created.byAge', {label: sum(1 for a in A if bucket(AGES[a['id']], AGE, None) == label) for label, _, _ in AGE}
              | ({'No creation date': no_date} if no_date else {}), 'apps')
NEW = sorted((a for a in A if AGES[a['id']] is not None and AGES[a['id']] <= WINDOW),
             key=lambda a: (-ts(a['createdDateTime']).timestamp(), by_name(a)))
NEW_ACCESS = [a for a in NEW if a['id'] in GRANTS or roles(a)]
new_delegated_only = sum(1 for a in NEW if a['id'] not in GRANTS and not roles(a) and a['id'] in DG)
new_window = fact('created.inWindow', {'apps': len(NEW), 'applicationPermissionsOrRoles': len(NEW_ACCESS), 'delegatedOnly': new_delegated_only,
                                       'none': len(NEW) - len(NEW_ACCESS) - new_delegated_only}, 'apps + api_assignments + delegated_grants')
fact('created.inWindowWithAccess', {a['id']: {'app': a['displayName'], 'created': created(a), 'permissions': len(GRANTS.get(a['id'], [])),
                                              'roles': [r for r, _ in roles(a)]} for a in NEW_ACCESS}, 'apps + api_assignments')

# ---------------------------------------------------------------- sign-in activity
rec = fact('signIn.recency', {label: sum(1 for a in A if bucket(days_before(a.get('lastSignInDateTime')), REC, NEVER) == label) for label, _, _ in REC}
           | {NEVER: sum(1 for a in A if not a.get('lastSignInDateTime'))}, 'apps')
quiet = fact('signIn.over45OrNever', rec['More than 45 days'] + rec[NEVER], 'apps')


def dormant_test(a):
    return bucket(days_before(a.get('lastSignInDateTime')), REC, NEVER) in ('More than 45 days', NEVER)


dormant = sorted((a for a in A if dormant_test(a) and (a['id'] in GRANTS or roles(a))),
                 key=lambda a: (-len(GRANTS.get(a['id'], [])), -len(roles(a)), by_name(a)))
dormant_delegated_only = fact('signIn.over45OrNeverDelegatedOnly', sum(1 for a in A if dormant_test(a) and a['id'] not in GRANTS
                                                                      and not roles(a) and a['id'] in DG), 'apps')
fact('signIn.over45OrNeverWithAppPermissionsOrRoles', [a['displayName'] for a in dormant], 'apps + api_assignments')

# ---------------------------------------------------------------- sections
tenant, as_of = R.tenant_raw, R.as_of
R.hero(f'Service principals in the {tenant} Microsoft 365 tenant, from data collected on {as_of}: publishers, the data apps can reach, directory roles, '
       f'application and delegated permissions, credentials, creation dates, consent and sign-in activity. Tables leave out the '
       f'{n(microsoft)} published by Microsoft.',
       scope=[('Not published by Microsoft', n(nonms), f'Of {n(total)} service principals'),
              ('This organization', n(by_group['This organization']), 'Registered in this tenant'),
              ('Other publishers', n(by_group['Other publishers']), 'Registered in another tenant'),
              ('No publisher tenant', n(by_group['No publisher tenant']), 'No owner tenant recorded')])
exp_foot = '. '.join(f'{label}: {n(exp_counts[kind]["Expired"])}' for kind, label, _ in CREDS)
R.kpis([
    {'kicker': 'Apps holding a privileged directory role', 'value': n(len(priv_apps)),
     'foot': f'Roles Microsoft marks privileged. Global Administrator: {n(len(ga_apps))}. Any directory role: {n(len(RA))}'},
    {'kicker': 'Apps with application permissions', 'value': n(len(PA)), 'unit': f' of {n(nonms)}',
     'foot': f'{n(grant_total)} permissions on {n(api_count)} APIs, used without a signed-in user'},
    {'kicker': 'Apps with an expired credential', 'value': n(len(expired_apps)), 'unit': f' of {n(nonms)}',
     'foot': f'{exp_foot}. Expiring within 30 days: {n(expiring_apps)}'},
    {'kicker': 'No sign-in in 45 days or never signed in', 'value': n(quiet), 'unit': f' of {n(nonms)}',
     'foot': f'Last sign-in more than 45 days ago: {n(rec["More than 45 days"])}. Never signed in: {n(rec[NEVER])}'},
])
R.add(diagram(D, HOLD, REACH, REACH_NAME, REACH_ROWS, reach_sub,
              'The figure beside each data area counts apps. Delegated grants of sign-in scopes only (' + ', '.join(SIGN_IN) +
              ') or of the app’s own folder aren’t drawn, so the delegated counts here can be lower than under Consent. Data '
              'areas take every permission, writing ones included, so a data area can count more apps than the company content '
              'tables below, which count permissions that read content.'), 'reach-map')
R.findings('app_findings_open', 'app_findings_accepted', ['ServicePrincipal'], 'Entra app findings')

scope = ('Recommended actions in scope: App Governance (AppG) and Defender for Cloud Apps (MCAS), plus the Entra ID actions IntegratedApps, '
         'aad_admin_consent_workflow and aad_third_party_apps on app consent and app registration. Microsoft’s Apps category is not '
         'shown: it scores Microsoft 365 services and connected cloud apps, not Entra app registrations')
_, below = R.secure_score('secure_score', 'secure_score_controls', None, scope)
below_ids = {c['id'] for c in below}
SERVICE_ORDER = ['AzureAD', 'AppG', 'MCAS']
rest = sorted((c for c in R.rows('secure_score_controls') if c['id'] not in below_ids),
              key=lambda c: (SERVICE_ORDER.index(c['service']) if c['service'] in SERVICE_ORDER else 9, c.get('rank') or 999, c['title']))
fact('secureScore.otherControlsInScope', {c['id']: {'points': c.get('controlScore.score'), 'max': c.get('maxScore')} for c in rest},
     'secure_score_controls')
if rest:
    R.S[-1]['panels'].append({
        'kicker': f'{"Other recommended actions" if below else "Recommended actions"} in scope: {n(len(rest))}',
        'cols': [{'key': 'title', 'label': 'Recommended action'}, {'key': 'service', 'label': 'Service'},
                 {'key': 'points', 'label': 'Points', 'n': True}, {'key': 'max', 'label': 'Maximum', 'n': True}],
        'rows': [{'title': {'text': D(c['title'])}, 'service': {'mono': D(c['service'])},
                  'points': num(c['controlScore.score']) if c.get('controlScore.score') is not None else 'No score',
                  'max': num(c['maxScore'])} for c in rest],
        'note': f'{esc(scope)}. No score: the collected action carries no points.'})

R.add({'type': 'panels', 'kicker': 'The estate', 'title': f'Service principals by publisher: {n(total)}', 'cols': 2, 'panels': [
    {'kicker': 'Publisher tenant', 'bars': bars(publisher_bars, total, quiet=('No publisher tenant',)),
     'note': 'From appOwnerOrganizationId, the tenant the app is registered in. Microsoft: Microsoft’s own tenants, listed under '
             'Definitions. Other publishers include apps registered in the consumer Microsoft account tenant.'},
    {'kicker': 'Service principal type', 'bars': bars(by_type, total),
     'note': f'From servicePrincipalType, whose values here are {esc(", ".join(D(t) for t in type_order))}. Microsoft documents '
             'ServiceIdentity as an agent identity and SocialIdp as for internal use.'},
    {'kicker': f'Not published by Microsoft: {n(nonms)}',
     'cols': [{'key': 'group', 'label': 'Publisher'}, {'key': 'apps', 'label': 'Apps', 'n': True}, {'key': 'on', 'label': 'Enabled', 'n': True},
              {'key': 'off', 'label': 'Disabled', 'n': True}, {'key': 'ms', 'label': 'Disabled by Microsoft', 'n': True}],
     'rows': [{'group': {'text': label}, 'apps': n(v['apps']), 'on': n(v['enabled']), 'off': n(v['disabled']), 'ms': n(v['disabledByMicrosoft'])}
              for label, v in status_rows.items()],
     'note': 'Enabled and Disabled: accountEnabled, which the Microsoft Entra admin center shows as Enabled for users to sign in. Disabled by '
             'Microsoft: Microsoft set disabledByMicrosoftStatus. Every table below covers these apps only.'},
    {'kicker': f'Other publishers by publisher verification: {n(len(OTHER))}', 'bars': bars(verified, len(OTHER), quiet=('No verified publisher',)),
     'note': f'Verified publisher: Microsoft’s verifiedPublisher on the app, from the publisher’s Partner Center account. '
             f'{n(len(publishers))} publisher names appear.'}]}, 'estate')

ms_note = (f'Microsoft-published apps holding a directory role: {n(ms_roles["apps"])} ('
           + ', '.join(f'{esc(D(r))}: {n(c)}' for r, c in sorted(ms_roles['byRole'].items(), key=lambda kv: (-kv[1], kv[0]))) + '). ') if ms_roles['apps'] else ''
role_check = check_name(PRIVILEGED_ROLE)
role_panel = {'kicker': f'Apps holding a directory role: {n(len(RA))}',
              'cols': [{'key': 'app', 'label': 'App'}, {'key': 'priv', 'label': 'Roles Microsoft marks privileged'},
                       {'key': 'other', 'label': 'Other roles'}, {'key': 'on', 'label': 'Enabled'}, {'key': 'last', 'label': 'Last sign-in'}],
              'rows': [{'app': app_cell(a), 'priv': {'text': ', '.join(D(r) for r, p in roles(a) if p) or 'None'},
                        'other': {'text': ', '.join(D(r) for r, p in roles(a) if not p) or 'None'},
                        'on': enabled(a), 'last': signed_in(a)} for a in RA],
              'note': f'{ms_note}Privileged: Microsoft’s isPrivileged flag on the role. Apps with a privileged role come first, Global Administrator '
                      'at the top. Active assignments only; roles eligible through PIM are not collected.'
                      + (f' The {role_check} check reads the same flag.' if role_check else '')}
perm_panel = {'kicker': f'Apps holding application permissions: {n(len(PA))}',
              'cols': [{'key': 'app', 'label': 'App'}, {'key': 'count', 'label': 'Permissions', 'n': True},
                       {'key': 'names', 'label': 'API and permission names'}, {'key': 'first', 'label': 'First granted'},
                       {'key': 'latest', 'label': 'Last granted'}, {'key': 'last', 'label': 'Last app-only sign-in'}],
              'rows': [{'app': app_cell(a), 'count': n(len(GRANTS[a['id']])), 'names': {'html': grant_html(a)}, 'first': granted(GRANTS[a['id']]),
                        'latest': granted(GRANTS[a['id']], last=True), 'last': signed_in(a, 'lastApplicationAuthenticationClientSignInDateTime')}
                       for a in PA],
              'note': f'By number of permissions. Read from each API’s list of assigned apps: an app’s own record lists at most {n(STORED_MAX)}, '
                      f'and {n(len(over_cap))} apps here hold more. Granted: createdDateTime on the app role assignment, when the permission was '
                      'assigned to the app. Last app-only sign-in: the app signed in with its own credential.'}
disabled_panel = {'kicker': f'Disabled apps holding permissions or roles: {n(len(disabled))}',
                  'cols': [{'key': 'app', 'label': 'App'}, {'key': 'app_p', 'label': 'Application permissions', 'n': True},
                           {'key': 'del_p', 'label': 'Delegated permissions', 'n': True}, {'key': 'roles', 'label': 'Directory roles'},
                           {'key': 'last', 'label': 'Last sign-in'}],
                  'rows': [{'app': app_cell(a), 'app_p': n(len(GRANTS.get(a['id'], []))), 'del_p': n(len({g[1] for g in DG.get(a['id'], [])})),
                            'roles': {'text': ', '.join(D(r) for r, _ in roles(a)) or 'None'}, 'last': signed_in(a)} for a in disabled],
                  'note': 'Apps with accountEnabled false that hold an application permission, a delegated permission grant or a directory role.'}
R.add({'type': 'panels', 'kicker': 'Roles and permissions', 'title': 'Directory roles and application permissions held by apps', 'cols': 1,
       'panels': [role_panel, perm_panel, disabled_panel]}, 'roles-and-permissions')


def content_html(a):
    """One line per way the app holds content permissions: <b>kind</b>: API: names."""
    c, lines = CONTENT_APPS[a['id']], []
    for k in GRANT_KINDS:
        per_api = defaultdict(list)
        for api, perm in c['kinds'][k]:
            per_api[api].append(perm)
        if per_api:
            who = f' ({n(len(c["users"]))} users)' if k == GRANT_KINDS[2] else ''
            lines.append(f'<b>{esc(k)}{who}</b>: ' + '; '.join(f'{esc(api)}: {esc(", ".join(sorted(p, key=str.lower)))}'
                                                             for api, p in sorted(per_api.items())))
    return '<br>'.join(lines)


content_note = ('Permissions counted, on ' + ', '.join(CONTENT_APIS) + ': names that start Mail.Read, Files.Read, Chat.Read, ChatMessage.Read, '
                'ChannelMessage.Read, Calendars.Read, Contacts.Read, Notes.Read, OnlineMeetingTranscript.Read, OnlineMeetingRecording.Read '
                'or OnlineMeetingArtifact.Read; Files.SelectedOperations; Sites read, read and write, manage and full control, and '
                'Sites.Selected; SharePoint’s AllSites and MyFiles; and Exchange’s full_access_as_app, EWS.AccessAsUser.All and IMAP and '
                'POP access. Files.ReadWrite.AppFolder, which reaches only the app’s own folder, is left out.')
R.add({'type': 'panels', 'kicker': 'Roles and permissions', 'title': f'Apps that can read company content: {n(len(CA_))}', 'cols': 2, 'panels': [
    {'kicker': f'By content area, of {n(len(CA_))} apps', 'bars': bars(content_by_area, len(CA_)),
     'note': 'An app counts once in each area its permissions reach. ' + content_note},
    {'kicker': f'By how the permission was granted, of {n(len(CA_))} apps', 'bars': bars(content_by_kind, len(CA_)),
     'note': 'Application permissions are used by the app itself, without a signed-in user. Admin consent for all users: a delegated grant '
             'of type AllPrincipals. User consent: a delegated grant for one user. An app can appear in more than one row.'}]},
      'content-access')
R.add({'type': 'panels', 'kicker': 'Roles and permissions', 'title': f'Content permissions by app: {n(len(CA_))}', 'cols': 1, 'panels': [
    {'cols': [{'key': 'app', 'label': 'App'}, {'key': 'areas', 'label': 'Content'}, {'key': 'perms', 'label': 'Permissions'},
              {'key': 'last', 'label': 'Last sign-in'}],
     'rows': [{'app': app_cell(a), 'areas': {'text': ', '.join(CONTENT_APPS[a['id']]['areas'])}, 'perms': {'html': content_html(a)},
               'last': signed_in(a)} for a in CA_],
     'note': 'Apps with application permissions first, then admin consent, then user consent, then by content areas and name. User '
             'consent: the users who granted it, counted in brackets.'} if CA_ else
    {'kicker': 'Apps: 0', 'note': 'No app not published by Microsoft holds a permission that reads company content.'}]}, 'content-apps')

R.add({'type': 'panels', 'kicker': 'Credentials', 'title': 'Client secrets, certificates and SAML signing certificates', 'cols': 1, 'panels': [
    {'kicker': f'Expired or expiring within 30 days: {n(len(EXP))}',
     'cols': [{'key': 'app', 'label': 'App'}, {'key': 'kind', 'label': 'Credential'}, {'key': 'rating', 'label': 'Rating'},
              {'key': 'end', 'label': 'Latest end date'}, {'key': 'on', 'label': 'Enabled'}, {'key': 'last', 'label': 'Last sign-in'}],
     'rows': [{'app': app_cell(a), 'kind': {'text': ONE[kind]}, 'rating': R.state(RATING[rating], rating, field),
               'end': R.day(end, none='No end date'), 'on': enabled(a), 'last': signed_in(a)} for a, kind, field, rating, end in EXP],
     'note': '. '.join(f'{label}: {n(exp_counts[kind]["Expired"])} expired, {n(exp_counts[kind]["Expiring"])} expiring within 30 days'
                       for kind, label, _ in CREDS)
             + '. One row per app and credential kind, by kind, rating and app name. The rating is the collector’s, from the latest-ending '
               'credential of each kind on the service principal and its app registration: Expired means every one has expired, and one '
               f'current credential hides expired ones. SAML signing certificates are the credentials named {esc(D(SAML))}; one with another '
               'name is rated as a client secret or certificate.'
             + (f' Certificates on {n(managed)} managed identities are rated {esc(MANAGED)} and not listed.' if managed else '')},
    {'kicker': f'Long-lived credentials: {n(len(LONG))}',
     'cols': [{'key': 'app', 'label': 'App'}, {'key': 'kind', 'label': 'Credential'}, {'key': 'where', 'label': 'Stored on'},
              {'key': 'start', 'label': 'Start date'}, {'key': 'end', 'label': 'End date'}, {'key': 'last', 'label': 'Last sign-in'}],
     'rows': [{'app': app_cell(a), 'kind': {'text': ONE[kind]}, 'where': {'text': where},
               'start': R.day(start), 'end': R.day(end), 'last': signed_in(a)} for a, kind, where, start, end in LONG],
     'note': f'Current credentials valid for more than {n(LONG_LIVED_YEARS)} years from their start date, by kind and end date. '
             'Managed identities are left out.'}]}, 'credentials')

R.add({'type': 'panels', 'kicker': 'Creation dates', 'title': 'When service principals were created in this tenant', 'cols': 1, 'panels': [
    {'kicker': f'Created, of {n(nonms)} apps', 'bars': bars(by_age, nonms, quiet=('No creation date',)),
     'note': 'From createdDateTime, when the service principal was created in this tenant, as Microsoft Graph returns it. For an app from '
             'another publisher this is when it was added to this tenant, not when the publisher registered it.'},
    {'kicker': f'Created in the {n(WINDOW)} days before collection, holding application permissions or a directory role: {n(len(NEW_ACCESS))}',
     'cols': [{'key': 'app', 'label': 'App'}, {'key': 'made', 'label': 'Created'}, {'key': 'perms', 'label': 'Application permissions', 'n': True},
              {'key': 'roles', 'label': 'Directory roles'}, {'key': 'on', 'label': 'Enabled'}, {'key': 'last', 'label': 'Last sign-in'}],
     'rows': [{'app': app_cell(a), 'made': created(a), 'perms': n(len(GRANTS.get(a['id'], []))),
               'roles': {'text': ', '.join(D(r) for r, _ in roles(a)) or 'None'}, 'on': enabled(a), 'last': signed_in(a)} for a in NEW_ACCESS],
     'note': f'Newest first. Of the {n(new_window["apps"])} apps created in the {n(WINDOW)} days before collection, '
             f'{n(new_window["delegatedOnly"])} hold delegated permissions only and {n(new_window["none"])} hold no permissions or roles.'}]},
      'created')

consent_check = check_name(RECENT_CONSENT)
R.add({'type': 'panels', 'kicker': 'Consent', 'title': 'Admin consent, user consent and grant dates', 'cols': 2, 'panels': [
    {'kicker': f'How permissions were granted, of {n(nonms)} apps', 'bars': bars(consent_types, nonms),
     'note': 'Application permissions are granted by an administrator. Admin consent for all users: a delegated grant of type AllPrincipals. '
             'User consent: a grant of type Principal, made for one user. An app can appear in more than one row.'},
    {'kicker': f'Application permissions by year granted: {n(grant_total)}', 'bars': bars(by_year | ({'No grant date': undated} if undated else {}),
                                                                                            grant_total, quiet=('No grant date',)),
     'note': 'From createdDateTime on each app role assignment, which Microsoft sets when the permission is assigned to the app. Delegated '
             'grants carry no date.'},
    {'kicker': f'Apps granted application permissions in the {n(WINDOW)} days before collection: {n(len(RG))}',
     'cols': [{'key': 'app', 'label': 'App'}, {'key': 'count', 'label': 'Permissions granted', 'n': True},
              {'key': 'first', 'label': 'First'}, {'key': 'latest', 'label': 'Last'}],
     'rows': [{'app': app_cell(a), 'count': n(len(RECENT[a['id']])), 'first': granted(RECENT[a['id']]),
               'latest': granted(RECENT[a['id']], last=True)} for a in RG],
     'note': 'From createdDateTime on each app role assignment, newest first. Delegated grants carry no date.'
             + (f' The {consent_check} check reads consent events from the Entra audit log, which this report does not use.' if consent_check else '')},
    {'kicker': f'Users with user consent grants: {n(len(user_rows))}',
     'cols': [{'key': 'user', 'label': 'User'}, {'key': 'apps', 'label': 'Apps', 'n': True}, {'key': 'names', 'label': 'App names'}],
     'rows': [{'user': {'text': user_name(u)}, 'apps': n(len(v)), 'names': {'text': ', '.join(D(a['displayName']) for a in v)}}
              for u, v in user_rows],
     'note': 'Users named in a delegated grant of type Principal.'}]}, 'consent')
R.add({'type': 'panels', 'kicker': 'Consent', 'title': f'Apps with user consent: {n(len(user_apps))}', 'cols': 1, 'panels': [{
    'cols': [{'key': 'app', 'label': 'App'}, {'key': 'users', 'label': 'Users who consented'},
             {'key': 'perms', 'label': 'Delegated permissions from user consent'}, {'key': 'last', 'label': 'Last sign-in'}],
    'rows': [{'app': app_cell(a), 'users': {'text': ', '.join(user_name(u) for u in consenters[a['id']])},
              'perms': {'text': ', '.join(sorted({g[1] for g in DG[a['id']] if g[2] == 'Principal'}, key=str.lower))}, 'last': signed_in(a)}
             for a in user_apps],
    'note': 'Collected data keeps one delegated grant per permission name for each app, so when an administrator and a user, or several users, '
            'granted the same permission, only one shows. Users can be undercounted.'}]}, 'user-consent')

sign_in_check = check_name(NOT_SIGNED_IN)
R.add({'type': 'panels', 'kicker': 'Sign-in activity', 'title': f'Last sign-in: {n(nonms)} apps not published by Microsoft', 'cols': 1, 'panels': [
    {'kicker': 'Last sign-in', 'bars': bars(rec, nonms, quiet=(NEVER,)),
     'note': 'From lastSignInDateTime, the latest of four sign-in flows: delegated or app-only, with the app as client or as the API called. '
             'Never signed in: Microsoft’s sign-in activity report holds no sign-in for the app.'
             + (f' The {sign_in_check} check reads the same field.' if sign_in_check else '')}]}, 'sign-in')
R.add({'type': 'panels', 'kicker': 'Sign-in activity',
       'title': f'No sign-in in 45 days or never signed in, holding application permissions or a directory role: {n(len(dormant))}',
       'cols': 1, 'panels': [{
           'cols': [{'key': 'app', 'label': 'App'}, {'key': 'perms', 'label': 'Application permissions', 'n': True},
                    {'key': 'roles', 'label': 'Directory roles'}, {'key': 'on', 'label': 'Enabled'}, {'key': 'made', 'label': 'Created'},
                    {'key': 'last', 'label': 'Last sign-in'}],
           'rows': [{'app': app_cell(a), 'perms': n(len(GRANTS.get(a['id'], []))), 'roles': {'text': ', '.join(D(r) for r, _ in roles(a)) or 'None'},
                     'on': enabled(a), 'made': created(a), 'last': signed_in(a)} for a in dormant],
           'note': f'By application permissions, then roles, then name. Another {n(dormant_delegated_only)} apps with no sign-in in 45 days or '
                   'never signed in hold delegated permissions only.'}]}, 'sign-in-access')

R.footer(f'Read-only collection on {as_of}. Values come from fixed queries of service principals, the apps assigned to each API, delegated '
         'permission grants, users, finding counts and Microsoft Secure Score, the same queries for every tenant. Every date is one Microsoft '
         'returns on the object or in its sign-in activity report.',
         'Microsoft-published: appOwnerOrganizationId is one of Microsoft’s tenants ' + ', '.join(MICROSOFT_TENANTS) + '. '
         'Application permission: an app role granted to the app itself, used without a signed-in user. Delegated permission: a scope the app '
         'uses on behalf of a signed-in user. Privileged role: Microsoft’s isPrivileged flag. Enabled: accountEnabled. Created: createdDateTime '
         'on the service principal. Sign-in dates use lastSignInDateTime.',
         'Microsoft-published apps outside the estate counts. Apps Microsoft publishes from tenants not listed above, which count as other '
         'publishers. App registrations with no service principal in this tenant. Roles eligible through PIM. Consent events in the Entra '
         'audit log, which Entra keeps 7 days without Microsoft Entra ID P1 or P2.')
R.write()
