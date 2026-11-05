"""App access recipe (folder app_access, id app-access), v0.2.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/app_access/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

What your apps can reach (2026-10-29: the July app access page as a fact recipe). Every app outside Microsoft's own that
holds a permission, by the data the permission reaches (mail, files and sites, Teams, calendars, contacts, notes and tasks,
directory data, access control, devices, security data, reports and other platforms) and how the app was given it:
application permissions, which act without a signed-in user; delegated permissions with admin consent for all users; and
delegated permissions individual users consented to.

Application permissions come from each API's list of assigned apps (appRoleAssignedTo) and carry Microsoft's label for the
app role, matched on appRoleId, because the permissionValue in an app's own list is wrong for seven Graph families
(I365-604). Delegated grants carry the permission names the grant records. Same inputs, same bytes.
"""
import pathlib, sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import Report, n  # noqa: E402
from app_reach import HOW, LABEL, ORDER, OWN_FOLDER, SHOW, SIGN_IN, area, diagram, diagram_rows, perm_html, tally, writes_text  # noqa: E402

R = Report(__file__, 'app-access', '0.2.0', 'App access report')
D, fact, when, day = R.D, R.fact, R.when, R.day

# ---------------------------------------------------------------- knowledge tables
# Microsoft tenants that publish apps (references/app-classification-convention.md); delegated_grants filters on the same list.
MICROSOFT_TENANTS = ['f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47',
                     'cdc5aeea-15c5-4db6-b079-fcadd2505dc2', '33e01921-4d64-4f8c-a055-5bdaffd5e33d',
                     '0d933fb8-3f65-4722-9430-08d60fc88af4', '975f013f-7f24-47e8-a7d3-abc4752bf346',
                     '47df5bb7-e6bc-4256-afb0-dd8c8e3c1ce8']
listed_ms = [f['value'] for q in R.spec['queries'] for f in q.get('filters', []) if f['field'] == 'appOwnerOrganizationId']
if sorted(listed_ms) != sorted(MICROSOFT_TENANTS):
    sys.exit('queries.json and MICROSOFT_TENANTS list different Microsoft tenants')

# Data areas, write rules and the ways of being given access are in app_reach.py, shared with the Entra apps report.
QUIET_DAYS = 45


def cols(rec, prefix, keys):
    arrays = [rec.get(f'{prefix}[].{k}') or [] for k in keys]
    if len({len(a) for a in arrays}) > 1:
        sys.exit(f'{prefix}[] arrays of {rec.get("displayName")!r} differ in length, so they cannot be paired')
    return [dict(zip(keys, row)) for row in zip(*arrays)]


# ---------------------------------------------------------------- the apps and every permission they hold
APPS = {a['id']: a for a in R.rows('client_apps')}
for a in R.rows('delegated_grants'):
    APPS.setdefault(a['id'], a)
NAME = {}
HOLD = defaultdict(lambda: defaultdict(set))  # app id -> how -> {(area, api, value, label)}
for api in R.rows('api_assignments'):
    roles = {r['id']: r for r in cols(api, 'appRoles', ['id', 'value', 'displayName'])}
    for a in cols(api, 'appRoleAssignedTo', ['principalId', 'principalDisplayName', 'principalType', 'appRoleId', 'createdDateTime']):
        role = roles.get(a['appRoleId'])
        if a['principalType'] != 'ServicePrincipal' or not role or not role.get('value'):
            continue
        NAME[a['principalId']] = a['principalDisplayName']
        HOLD[a['principalId']]['application'].add((area(api['displayName'], role['value']), api['displayName'], role['value'],
                                                   role.get('displayName') or role['value']))
quiet_only = set()  # apps whose every grant is a sign-in scope or the app's own folder
for a in R.rows('delegated_grants'):
    NAME.setdefault(a['id'], a['displayName'])
    kept = 0
    for g in cols(a, 'oauth2PermissionGrants', ['resourceDisplayName', 'permissionValue', 'consentType', 'principalId']):
        if not g['permissionValue'] or g['permissionValue'] in SIGN_IN or g['permissionValue'] == OWN_FOLDER:
            continue
        kept += 1
        how = 'admin' if g['consentType'] == 'AllPrincipals' else 'user'
        HOLD[a['id']][how].add((area(g['resourceDisplayName'], g['permissionValue']), g['resourceDisplayName'], g['permissionValue'],
                                g['permissionValue']))
    if not kept and not HOLD[a['id']]['application']:
        quiet_only.add(a['id'])
for a in R.rows('role_apps'):
    APPS.setdefault(a['id'], a)
    NAME.setdefault(a['id'], a['displayName'])


def microsoft(i):
    return (APPS.get(i) or {}).get('appOwnerOrganizationId') in MICROSOFT_TENANTS


listed = sorted((i for i in HOLD if not microsoft(i) and any(HOLD[i].values())), key=lambda i: (NAME[i].casefold(), i))
by_how = {h: [i for i in listed if HOLD[i][h]] for h in HOW}
how_n = fact('apps.byGrant', {HOW[h]: len(v) for h, v in by_how.items()}, 'api_assignments + delegated_grants')
fact('apps.withPermissions', len(listed), 'api_assignments + delegated_grants')
ms_n = fact('apps.microsoftWithApplicationPermissions', sum(1 for i in HOLD if microsoft(i) and HOLD[i]['application']),
            'api_assignments + client_apps')
quiet_n = fact('apps.signInOrOwnFolderOnly', len(quiet_only), 'delegated_grants')
sp_total = fact('scope.servicePrincipals', R.total('apps_by_category'), 'apps_by_category')
ROLE_APPS = sorted((a for a in R.rows('role_apps') if not microsoft(a['id'])), key=lambda a: (a['displayName'].casefold(), a['id']))
role_ms_n = fact('roles.microsoftApps', sum(1 for a in R.rows('role_apps') if microsoft(a['id'])), 'role_apps')
global_admins = fact('roles.globalAdministratorApps', sum(1 for a in ROLE_APPS if 'Global Administrator' in (a.get('directoryRoles[].displayName') or [])), 'role_apps')
fact('roles.apps', [{'app': a['displayName'], 'roles': a.get('directoryRoles[].displayName') or []} for a in ROLE_APPS], 'role_apps')
SAME = defaultdict(set)
for i in set(listed) | {a['id'] for a in ROLE_APPS}:
    SAME[NAME[i]].add(i)

# ---------------------------------------------------------------- data area by grant type
CELL, AREA_APPS, _ = tally(HOLD, listed)
fact('areas.byGrant', {LABEL[ar]: {HOW[h]: {'apps': len(CELL[ar][h]['apps']), 'write': len(CELL[ar][h]['write'])} for h in HOW}
                       for ar in SHOW}, 'api_assignments + delegated_grants')
fact('areas.apps', {LABEL[ar]: len(AREA_APPS[ar]) for ar in SHOW}, 'api_assignments + delegated_grants')
# Application permissions that read mail: the mailbox access report's set, so both reports count the same apps.
READS_MAIL = {'Mail.Read', 'Mail.ReadWrite', 'Mail.ReadBasic', 'Mail.ReadBasic.All', 'MailboxItem.Read.All', 'MailboxItem.ImportExport.All',
              'MailboxFolder.Read.All', 'MailboxFolder.ReadWrite.All', 'full_access_as_app', 'IMAP.AccessAsApp', 'POP.AccessAsApp',
              'EWS.AccessAsApp'}
read_mail = fact('kpi.applicationReadsMail', sum(1 for i in by_how['application'] if any(
    api in ('Microsoft Graph', 'Office 365 Exchange Online') and v in READS_MAIL for _, api, v, _ in HOLD[i]['application'])),
    'api_assignments')


def last_signin(i):
    return when((APPS.get(i) or {}).get('lastSignInDateTime'))


app_quiet = fact('apps.applicationNoSignIn45', sum(1 for i in by_how['application'] if i in APPS and (
    last_signin(i) is None or R.age(last_signin(i)) > QUIET_DAYS)), 'client_apps')

# ================================================================ sections
R.hero('Every app outside Microsoft’s own that holds a permission or a directory role, by the data each permission reaches and how '
       'the app was given it.',
       scope=[('Apps with permissions', n(len(listed)), 'Not published by Microsoft'),
              (HOW['application'], n(how_n[HOW['application']]), f'No sign-in in {QUIET_DAYS} days: {n(app_quiet)}'),
              (HOW['admin'], n(how_n[HOW['admin']])), (HOW['user'], n(how_n[HOW['user']]))])
R.kpis([
    {'kicker': 'Apps that can reach mail', 'value': n(len(AREA_APPS['mail'])), 'foot': f'Application permissions that read mail: {n(read_mail)}'},
    {'kicker': 'Apps that can reach files and sites', 'value': n(len(AREA_APPS['files'])),
     'foot': f'With application permissions: {n(len(CELL["files"]["application"]["apps"]))}'},
    {'kicker': 'Apps that can change access control', 'value': n(len(AREA_APPS['control'])),
     'foot': 'Roles, consent, app credentials, policies, domains or sign-in methods'},
    {'kicker': 'Apps with directory roles', 'value': n(len(ROLE_APPS)), 'foot': f'Global Administrator: {n(global_admins)}'},
])


def cell(ar, h):
    c = CELL[ar][h]
    return {'text': n(len(c['apps'])), 'sub': f'Write: {n(len(c["write"]))}'} if c['apps'] else '0'


R.add({'type': 'panels', 'kicker': 'Where apps reach', 'title': 'Apps by the data they reach and how they were given it', 'cols': 1, 'panels': [{
    'cols': [{'key': 'area', 'label': 'Data'}, {'key': 'app', 'label': HOW['application']}, {'key': 'admin', 'label': HOW['admin']},
             {'key': 'user', 'label': HOW['user']}, {'key': 'all', 'label': 'Apps', 'n': True}],
    'rows': [{'area': {'text': LABEL[ar]}, 'app': cell(ar, 'application'), 'admin': cell(ar, 'admin'), 'user': cell(ar, 'user'),
              'all': n(len(AREA_APPS[ar]))} for ar in SHOW],
    'note': 'Each cell counts apps, and an app can count in several. Application permissions act without a signed-in user, at the full '
            'level the permission names, across the tenant. Delegated permissions act as the signed-in user and reach only what that '
            'user can reach; admin consent for all users lets anyone who signs in to the app use them. Write: the permission name grants '
            'more than reading, such as ReadWrite, Send, Manage, FullControl, AccessAs, Create, Delete or Remove. Sites.Selected and the '
            'other permissions ending Selected set their access on each site or item, and aren’t counted as write.'}]}, 'matrix')


def app_cell(i, count):
    a = APPS.get(i) or {}
    pub = a.get('verifiedPublisher.displayName')
    bits = [f'Verified publisher: {D(pub)}' if pub else 'No verified publisher']
    if a.get('accountEnabled') is False:
        bits.append('Disabled')
    if count > 1:
        bits.append(f'Service principals with this name and these permissions: {n(count)}')
    elif len(SAME[NAME[i]]) > 1:
        bits.append('Another service principal has the same name')
    return {'text': D(NAME[i]), 'sub': ' · '.join(bits)}


def signin(i):
    if i not in APPS:
        return 'No app record in the collected data'
    return day(last_signin(i), none='No sign-in recorded')


ROWS = {ar: defaultdict(list) for ar in SHOW}  # area -> row key -> app ids
for i in listed:
    for h in HOW:
        per = defaultdict(set)
        for ar, api_name, value, label in HOLD[i][h]:
            per[ar].add((api_name, value, label))
        for ar, perms in per.items():
            perms = tuple(sorted(perms, key=lambda p: (p[0].casefold(), p[1].casefold())))
            a = APPS.get(i) or {}
            key = (h, NAME[i], perms, signin(i), a.get('verifiedPublisher.displayName'), a.get('accountEnabled'))
            ROWS[ar][key].append(i)

def row_sort(item):
    (h, name, perms, *_), ids = item
    return ORDER.index(h), writes_text(perms) != 'Yes', name.casefold(), ids[0]


fact('areas.rows', {LABEL[ar]: [{'app': k[1], 'access': HOW[k[0]], 'servicePrincipals': len(ids), 'writes': writes_text(k[2]),
                                 'permissions': [f'{api}: {v}' for api, v, _ in k[2]]} for k, ids in sorted(ROWS[ar].items(), key=row_sort)]
                    for ar in SHOW}, 'api_assignments + delegated_grants')

# ---------------------------------------------------------------- app-to-data diagram (app_reach.py)
NODES = diagram_rows(HOLD, listed, NAME, lambda i: ((APPS.get(i) or {}).get('verifiedPublisher.displayName'),
                                                   (APPS.get(i) or {}).get('accountEnabled'), signin(i)))
fact('diagram.rows', [{'app': NAME[ids[0]], 'servicePrincipals': len(ids)} for ids in NODES], 'api_assignments + delegated_grants')


def diagram_sub(ids):
    i = ids[0]
    d = last_signin(i) if i in APPS else None
    last = ('No app record in the collected data' if i not in APPS else f'Last sign-in: {day(d)}' if d else 'No sign-in recorded')
    return f'{app_cell(i, len(ids))["sub"]} · {last}'


R.add(diagram(D, HOLD, listed, NAME, NODES, diagram_sub, 'The figure beside each data area counts apps, as in the table above.'),
      'reach-map')

R.add({'type': 'parthead', 'kicker': 'By data area', 'title': 'The apps that hold each kind of access',
       'sub': 'One table for each data area, application permissions first, then delegated permissions with admin consent for all '
              'users, then delegated permissions from user consent. Application permissions show Microsoft’s label for the app role with its name in brackets; delegated '
              'permissions show the names the grant records. Permissions are on Microsoft Graph unless another API is named.'}, 'areas')
AREA_NOTE = {
    'mail': 'Exchange.ManageAsApp lets an app run Exchange Online PowerShell without a signed-in user; what it can change follows the '
            'directory roles assigned to the app, listed under Directory roles below.',
    'files': 'Sites.Selected reaches only the sites an administrator granted the app, at the access set on each site.',
    'control': 'Permissions that change role assignments, permission grants and consent, app credentials, policies, domains, identity '
               'providers or users’ sign-in methods, passwords and account state.',
    'other': 'Permissions on other APIs, such as Azure, Power Platform, Power BI and Partner Center, and Microsoft Graph permissions '
             'outside the areas above.'}
for ar in SHOW:
    rows = sorted(ROWS[ar].items(), key=row_sort)
    panel = {'kicker': f'Apps: {n(len(AREA_APPS[ar]))}',
             'cols': [{'key': 'app', 'label': 'App'}, {'key': 'how', 'label': 'Access'}, {'key': 'perm', 'label': 'Permissions'},
                      {'key': 'rw', 'label': 'Writes'}, {'key': 'last', 'label': 'Last sign-in'}],
             'rows': [{'app': app_cell(ids[0], len(ids)), 'how': HOW[k[0]], 'perm': {'html': perm_html(D, k[0], k[2])},
                       'rw': writes_text(k[2]), 'last': k[3]} for k, ids in rows]}
    if ar in AREA_NOTE:
        panel['note'] = AREA_NOTE[ar]
    if not rows:
        panel = {'kicker': f'Apps: {n(0)}', 'note': 'No app outside Microsoft’s own holds a permission in this area.'}
    R.add({'type': 'panels', 'kicker': 'By data area', 'title': LABEL[ar], 'cols': 1, 'panels': [panel]}, f'area-{ar}')

ROLE_ORDER = ['Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator', 'Security Administrator',
              'Conditional Access Administrator', 'Application Administrator', 'Cloud Application Administrator', 'Exchange Administrator',
              'SharePoint Administrator', 'Teams Administrator', 'User Administrator', 'Intune Administrator', 'Compliance Administrator',
              'Directory Writers', 'Global Reader', 'Directory Readers']


def role_rank(a):
    roles = a.get('directoryRoles[].displayName') or []
    return min((ROLE_ORDER.index(r) if r in ROLE_ORDER else len(ROLE_ORDER) for r in roles), default=len(ROLE_ORDER))


R.add({'type': 'panels', 'kicker': 'Directory roles', 'title': 'Apps that hold directory roles', 'cols': 1, 'panels': [{
    'kicker': f'Apps: {n(len(ROLE_APPS))}',
    'cols': [{'key': 'app', 'label': 'App'}, {'key': 'roles', 'label': 'Directory roles'}, {'key': 'last', 'label': 'Last sign-in'}],
    'rows': [{'app': app_cell(a['id'], 1), 'roles': {'text': ', '.join(D(r) for r in sorted(a.get('directoryRoles[].displayName') or [],
                                                                                            key=lambda r: (r not in ROLE_ORDER, ROLE_ORDER.index(r) if r in ROLE_ORDER else 0, r)))},
              'last': day(when(a.get('lastSignInDateTime')), none='No sign-in recorded')}
             for a in sorted(ROLE_APPS, key=lambda a: (role_rank(a), a['displayName'].casefold(), a['id']))],
    'note': f'A directory role gives an app everything the role allows, on top of its permissions. Microsoft-published apps with '
            f'directory roles are counted, not listed: {n(role_ms_n)}.'}]}, 'roles')

R.add({'type': 'panels', 'kicker': 'Data limits', 'title': 'What the collected data doesn’t hold', 'cols': 1, 'panels': [{
    'cols': [{'key': 'what', 'label': 'Not in the collected data'}, {'key': 'where', 'label': 'Where it lives'}],
    'rows': [{'what': 'Which sites a Sites.Selected grant covers, and the access set on each', 'where': {'mono': 'GET /sites/{id}/permissions'}},
             {'what': 'Application access policies and RBAC for Applications, which narrow an app’s mailbox reach',
              'where': {'mono': 'Get-ApplicationAccessPolicy, Get-ManagementRoleAssignment'}},
             {'what': 'Every user who consented to a permission: the collected data keeps one delegated grant per permission for each app, '
                      'so a personal grant can sit behind a tenant-wide one', 'where': {'mono': 'GET /oauth2PermissionGrants'}},
             {'what': 'Who signs in to each app, which bounds what its delegated permissions reach', 'where': 'Microsoft Entra sign-in logs'}],
    'note': f'Counted, not listed: apps whose only delegated grants are sign-in scopes ({", ".join(SIGN_IN)}) or '
            f'{OWN_FOLDER}, which reaches only the app’s own folder: {n(quiet_n)}. Microsoft-published apps with application permissions: '
            f'{n(ms_n)}.'}]}, 'data-limits')
R.footer(f'One collection on {R.as_of}. Application permissions from each API’s assigned apps, named by Microsoft’s labels; delegated '
         'grants from each app outside Microsoft’s own; directory roles and app details from the service principals.',
         'Data areas group permissions by name, as the table notes describe. Microsoft-published: appOwnerOrganizationId is one of '
         'Microsoft’s tenants ' + ', '.join(MICROSOFT_TENANTS) + '.',
         'Microsoft-published apps; apps whose only delegated grants are sign-in scopes or their own folder; the data limits above.')
R.write()
