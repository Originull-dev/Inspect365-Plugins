"""What each app's permissions reach, shared by the app access and Entra apps recipes, so both group permissions into the
same data areas and draw the same app-to-data diagram (2026-11-03: the diagram goes at the top of the Entra apps report
too).

A holding is (data area, API, permission name, label): the label is Microsoft's name for an application permission's app
role, and the permission name itself for a delegated grant. hold maps an app id to its holdings under each way of being
given access (HOW), as a defaultdict of sets. Same inputs, same bytes.
"""
import re
from collections import defaultdict

from common import esc, n

# The data each permission reaches, by permission name, matching case-insensitively (the July app access page's areas).
# Names are matched on the APIs below; another API's permissions take that API's area, else other permissions. Access
# control comes first, so a permission that changes roles, grants, app credentials, policies, domains or sign-in methods
# counts there and its read-only form counts as directory data.
NAMED_APIS = ('Microsoft Graph', 'Windows Azure Active Directory', 'Office 365 Exchange Online', 'Office 365 SharePoint Online')
AREAS = [
    ('control', 'Identity and access control',
     r'(AppRoleAssignment|RoleManagement|RoleManagementPolicy|RoleAssignmentSchedule|RoleEligibilitySchedule|Application|'
     r'DelegatedPermissionGrant|Policy|UserAuthenticationMethod|User-PasswordProfile|PrivilegedAccess|PrivilegedAssignmentSchedule|'
     r'PrivilegedEligibilitySchedule|Domain|IdentityProvider|EntitlementManagement|DelegatedAdminRelationship|ConsentRequest)'
     r'\.(ReadWrite|ReadApprove|Remove).*|User\.(EnableDisableAccount|ManageIdentities)\..*', ()),
    ('mail', 'Email and mailboxes',
     r'Mail\w*\..*|(EWS|EAS|IMAP|POP|SMTP)\..*|full_access_as_(app|user)|Exchange\.Manage.*|Group-Conversation\..*|ExchangeMessageTrace\..*',
     ('Office 365 Exchange Online', 'Microsoft Exchange Online Protection')),
    ('files', 'Files, SharePoint and OneDrive', r'(Files?|Sites|AllSites|MyFiles|TermStore|SharePoint|List|ListItem|AllProfiles)\w*\..*',
     ('Office 365 SharePoint Online',)),
    ('teams', 'Teams, chats and meetings', r'(Chat|Channel|Team|OnlineMeeting|Call|Presence|VirtualEvent|Schedule|AppCatalog)\w*\..*', ()),
    ('calendars', 'Calendars', r'(Calendars?|Place)\w*\..*', ()),
    ('contacts', 'Contacts and people', r'(Contacts|People|OrgContact)\..*', ()),
    ('notes', 'Notes, tasks and bookings', r'(Notes|Tasks|Bookings)\w*\..*', ()),
    ('directory', 'Directory and identity data',
     r'(User|Users|Group|GroupMember|Directory|Organization|OrgSettings|Domain|AdministrativeUnit|Member|RoleManagement|'
     r'RoleAssignmentSchedule|RoleEligibilitySchedule|Application|AppRoleAssignment|DelegatedPermissionGrant|Policy|LicenseAssignment|'
     r'CustomSecAttribute|PrivilegedAccess|PrivilegedAssignmentSchedule|PrivilegedEligibilitySchedule|IdentityProvider|'
     r'EntitlementManagement|AccessReview|Agreement|ProfilePhoto|LifecycleWorkflows|Synchronization|OnPremDirectorySynchronization|'
     r'DelegatedAdminRelationship|ConsentRequest|CrossTenantInformation|CustomAuthenticationExtension|IdentityUserFlow|PeopleSettings|'
     r'UnifiedGroupMember|MultiTenantOrganization|ProgramControl)\w*[.-].*', ()),
    ('devices', 'Device and endpoint management', r'(Device|BitlockerKey|WindowsUpdates|CloudPC)\w*\..*', ('Microsoft Intune API',)),
    ('security', 'Security and threat data',
     r'(Security|Threat|IdentityRisk|InformationProtection|eDiscovery|RecordsManagement|AttackSimulation|CustomDetection|Sensitivity|'
     r'DataLossPrevention|CloudApp|NetworkAccess)\w*[.-].*', ('WindowsDefenderATP', 'Microsoft Threat Protection', 'Microsoft Cloud App Security')),
    ('reports', 'Reports, audit and activity', r'(Reports|ReportSettings|AuditLog|ActivityFeed|ServiceHealth|ServiceMessage)\w*\..*',
     ('Office 365 Management APIs',)),
]
LABEL = {k: label for k, label, _, _ in AREAS} | {'other': 'Other permissions'}
SHOW = ['mail', 'files', 'teams', 'calendars', 'contacts', 'notes', 'directory', 'control', 'devices', 'security', 'reports', 'other']
# Delegated sign-in scopes, and Files.ReadWrite.AppFolder, which reaches only the app's own folder: counted, not listed.
SIGN_IN = ['openid', 'profile', 'email', 'offline_access', 'User.Read']
OWN_FOLDER = 'Files.ReadWrite.AppFolder'
# Write: an action segment of the name beyond reading, or one of three whole names.
WRITE = re.compile(r'(ReadWrite|Write|Send|Manage|FullControl|AccessAs|ImportExport|Create|Delete|Update|ReadUpdate|ReadApprove|'
                   r'Invite|EnableDisable|PasswordProfile|PrivilegedOperations|Initiate|Join|Remove|Edit|Migrate|Command|Revoke|Submit)\w*', re.I)
WRITE_NAMES = {'full_access_as_app', 'full_access_as_user', 'user_impersonation'}
SELECTED = re.compile(r'.*\.Selected', re.I)   # Sites.Selected and *.SelectedOperations.Selected: the access is set per site or item
# Microsoft's terms, as the Entra apps report labels them (2026-07-23: Application against Delegated, with the consent
# scope spelled out).
HOW = {'application': 'Application permissions', 'admin': 'Delegated, admin consent for all users', 'user': 'Delegated, user consent'}
ORDER = list(HOW)


def area(api, value):
    for key, _, rx, _ in AREAS:
        if api in NAMED_APIS and re.fullmatch(rx, value, re.I):
            return key
    return next((key for key, _, _, apis in AREAS if api in apis), 'other')


def writes(value):
    """True, False, or None when the access is set where the permission is granted (Sites.Selected)."""
    if SELECTED.fullmatch(value):
        return None
    return value in WRITE_NAMES or any(WRITE.fullmatch(p) for p in value.replace('-', '.').split('.')[1:])


def writes_text(perms):
    w = [writes(v) for _, v, _ in perms]
    return 'Yes' if any(w) else ('Set per site or item' if None in w else 'No')


def perm_html(D, h, perms):
    lines = []
    for api, v, lab in perms:
        line = f'{esc(D(lab))} <span class="mono">({esc(D(v))})</span>' if h == 'application' and lab != v else f'<span class="mono">{esc(D(v))}</span>'
        lines.append(line if api == 'Microsoft Graph' else f'{line} · {esc(D(api))}')
    return '<br>'.join(lines)


def tally(hold, listed):
    """For each data area and way of access, the listed apps holding a permission there and those that can write; then each
    area's apps and each way's apps."""
    cell = {ar: {h: {'apps': set(), 'write': set()} for h in HOW} for ar in SHOW}
    for i in listed:
        for h in HOW:
            for ar, api_name, value, label in hold[i][h]:
                cell[ar][h]['apps'].add(i)
                if writes(value):
                    cell[ar][h]['write'].add(i)
    area_apps = {ar: set().union(*(cell[ar][h]['apps'] for h in HOW)) for ar in SHOW}
    by_how = {h: [i for i in listed if hold[i][h]] for h in HOW}
    return cell, area_apps, by_how


# ---------------------------------------------------------------- app-to-data diagram (2026-10-29: the July page's diagram)
# Apps on the left, data areas on the right, one line for each app and area, in four views: all apps, then each way of being
# given access. The build places every bar and line; the page draws them and isolates an app or a data area on click. Units
# are SVG units, which the page scales to its width: app labels end at AX, lines run from the app bars to the data area bars
# at RX, LINE units apart, and every app row and data area is at least ROW tall so its label fits.
W, AX, RX, BAR, LINE, ROW, GAP = 1000, 300, 694, 6, 4, 15, 3
AREA_IX = {ar: k for k, ar in enumerate(SHOW)}


def diagram_rows(hold, listed, name, same):
    """Service principals with the same name and the same permissions share one row, as in the tables, when same(i) also
    matches."""
    groups = defaultdict(list)
    for i in listed:
        held = tuple(sorted((h, ar, api, v) for h in HOW for ar, api, v, _ in hold[i][h]))
        groups[(name[i], held) + same(i)].append(i)
    return sorted(groups.values(), key=lambda ids: (name[ids[0]].casefold(), ids[0]))


def diagram(D, hold, listed, name, nodes, sub, note_end):
    """The diagram section for R.add. sub(ids) is the line under a row's app name; note_end closes the note."""
    cell, area_apps, by_how = tally(hold, listed)

    def reach(i, view):
        """The data areas app i reaches in a view, each with whether any of its permissions there writes."""
        out = {}
        for h in (HOW if view == 'all' else [view]):
            for ar, api, v, _ in hold[i][h]:
                out[ar] = out.get(ar, False) or bool(writes(v))
        return out

    def layout(view):
        """Apps sorted by the mean position of the areas they reach, so lines fan out with few crossings; each bar's lines in
        the order of the bars at their other end, so no two cross inside a bar."""
        rows = {k: reach(ids[0], view) for k, ids in enumerate(nodes)}
        order = sorted((k for k in rows if rows[k]), key=lambda k: (sum(AREA_IX[ar] for ar in rows[k]) / len(rows[k]), -len(rows[k]),
                                                                   name[nodes[k][0]].casefold(), nodes[k][0]))
        users = {ar: [k for k in order if ar in rows[k]] for ar in SHOW}
        left = sum(max(len(rows[k]) * LINE, ROW) for k in order) + GAP * (len(order) - 1)
        right = sum(max(len(users[ar]) * LINE, ROW) for ar in SHOW)
        H = max(left, right + GAP * (len(SHOW) - 1))
        y, apps, start = (H - left) / 2, [], {}
        for k in order:
            h = len(rows[k]) * LINE
            top = y + (max(h, ROW) - h) / 2
            apps.append([k, round(top, 1), h])
            for j, ar in enumerate(sorted(rows[k], key=AREA_IX.get)):
                start[(k, ar)] = top + j * LINE + LINE / 2
            y += max(h, ROW) + GAP
        y, gap, areas, links = 0, (H - right) / (len(SHOW) - 1), [], []
        for ar in SHOW:
            h = len(users[ar]) * LINE
            top = y + (max(h, ROW) - h) / 2
            areas.append([AREA_IX[ar], round(top, 1), h, n(len(area_apps[ar]) if view == 'all' else len(cell[ar][view]['apps']))])
            for j, k in enumerate(users[ar]):
                links.append([k, AREA_IX[ar], round(start[(k, ar)], 1), round(top + j * LINE + LINE / 2, 1), int(rows[k][ar])])
            y += max(h, ROW) + gap
        return {'h': round(H, 1), 'apps': apps, 'areas': areas, 'links': links}

    def app(ids):
        i, rows = ids[0], []
        for h in HOW:
            per = defaultdict(set)
            for ar, api, v, lab in hold[i][h]:
                per[ar].add((api, v, lab))
            for ar, perms in per.items():
                perms = tuple(sorted(perms, key=lambda p: (p[0].casefold(), p[1].casefold())))
                rows.append({'k': h, 'r': AREA_IX[ar], 'area': LABEL[ar], 'how': HOW[h], 'perm': {'html': perm_html(D, h, perms)},
                             'rw': writes_text(perms)})
        return {'label': D(name[i]), 'count': n(len(ids)) if len(ids) > 1 else None, 'sub': sub(ids),
                'rows': sorted(rows, key=lambda r: (r['r'], ORDER.index(r['k'])))}

    detail = [{'key': 'how', 'label': 'Access'}, {'key': 'perm', 'label': 'Permissions'}, {'key': 'rw', 'label': 'Writes'}]
    return {'type': 'sankey', 'kicker': 'App to data', 'title': 'Which apps reach which data',
            'sub': 'Each line joins an app to a data area it reaches. Select an app or a data area to keep only its lines and list the '
                   'permissions behind them; select it again to clear.',
            'geom': {'w': W, 'ax': AX, 'rx': RX, 'bar': BAR, 'line': LINE},
            'legend': [{'label': 'Writes', 'color': 'var(--series-1)'}, {'label': 'Reads', 'color': 'var(--neutral-mark)'}],
            'views': [dict(key='all', label='All apps', count=n(len(listed)), **layout('all'))] +
                     [dict(key=h, label=HOW[h], count=n(len(by_how[h])), **layout(h)) for h in HOW],
            'areas': [LABEL[ar] for ar in SHOW], 'apps': [app(ids) for ids in nodes],
            'appCols': [{'key': 'area', 'label': 'Data'}] + detail, 'areaCols': [{'key': 'app', 'label': 'App'}] + detail,
            'note': 'A line is blue when at least one of its permissions writes and gray when they only read; Sites.Selected and the other '
                    'permissions ending Selected count as reading, since their access is set on each site or item. Service principals with '
                    'the same name and the same permissions share one row, with their number after the name. ' + note_end}
