"""SharePoint permissions report: who can open each SharePoint site and each document library, from Inspect 365 data.

The model and the flat report page for the recipe `sharepoint-permissions`. build.py in this folder runs it on a recipe run folder;
explorer.py builds the second page, the Explorer, from the same model.

How the data is read (the rules are written into the report's notes too):
- Sites: every SharePoint site but OneDrive, grouped by what each is connected to: SharePoint only, a Microsoft 365
  group that is not in Teams, or Teams (Teams-connected sites and Teams channel sites).
- A library that inherits has the access of the web it inherits from (inheritsFromId), so it points there. A library
  with its own permissions lists its own grants only. Site collection administrators always appear, because they keep
  Full Control everywhere.
- Access is shown as SharePoint grants it: Model.rows(sec) gives one row per SharePoint group, one for site admins and
  one per level granted directly. Groups are expanded by the Collector (assignments[].through); a group whose
  membership is not known is listed as such. Each group's people are kept once and printed once, under Groups.
  Everyone and Everyone except external users are never expanded; the second is counted in every total and shown
  first, as Everyone in the organization.
- A level's tier (full control, can edit, can view) comes from the rights the level carries, not from its name. Since
  MCP knowledge 2026-11-23.1 a grant's entries carry no rights: normalize() joins them from
  sharepoint-permission-levels and checks the tier against the server's access level on every entry.
- A SharePoint group that is granted a level and has no one in it has no grant; Model.empty_groups(sec) finds it in the
  web's or library's own role assignments. It is listed outside every count.
- Sharing inside a library (links, files shared directly) is not shown: most of it can't be reported in full.

A caller sets TENANT, TENANT_NAME and APP, points DATA at the folder to write to, and replaces load() (and load_links()
where it has Teams channel links) before calling build(). Standard library only.
"""
import datetime as dt
import hashlib
import html
import json
import pathlib
from collections import defaultdict

HERE = pathlib.Path(__file__).resolve().parent
_HOME = HERE   # build() writes beside the data unless a caller points HERE somewhere else
DATA = HERE    # where load() reads data.json and build() writes the pages
REPO = HERE    # paths under it print relative
TENANT = ''
TENANT_NAME = ''
APP = 'https://us.inspect365.app'  # links into the app, in the MSP's copy only
LINKS_FILE = DATA / 'links.json'
SHARING_FILE = DATA / 'sharing.json'
ROLE_NAMES = {}  # directory role id -> Entra name, for pulls from before a grant's title was the Entra name
LINK_KINDS = {'AnonymousEdit': 'anyone with the link can edit', 'AnonymousView': 'anyone with the link can view',
              'OrganizationEdit': 'anyone in the organization can edit', 'OrganizationView': 'anyone in the organization can view',
              'Flexible': 'only the people it was shared with can use'}


def app_url(kind, oid, tab=None):
    return f"{APP}/asset/{kind}/{oid}?" + (f'tab={tab}&' if tab else '') + f'tenant={TENANT}'


# What a site is connected to decides where its access is managed (learn.microsoft.com/sharepoint/teams-connected-sites,
# learn.microsoft.com/sharepoint/modern-experience-sharing-permissions). "Team site, private group" doesn't say
# whether a site is SharePoint only or tied to Teams, or where to go to manage it.
CATEGORIES = [('sp', 'SharePoint only'), ('group', 'Microsoft 365 group sites, not in Teams'), ('teams', 'Teams-connected and channel sites')]
PLURAL = {'sp': 'SharePoint-only sites', 'group': 'Microsoft 365 group sites not in Teams', 'teams': 'Teams-connected and channel sites'}
DEFAULT_KINDS = ('sp', 'group', 'teams')  # every kind: the pull holds all of it, and the Explorer lets readers pick


def join_and(words):
    words = list(words)
    return ' and '.join(words) if len(words) < 3 else ', '.join(words[:-1]) + ' and ' + words[-1]


# ---------- model ----------

def load():
    return normalize(json.loads((DATA / 'data.json').read_text()))


def load_links():
    """Optional extras: {'teams': teams with their channels, 'prodSites': another server's site ids by address}."""
    return json.loads(LINKS_FILE.read_text()) if LINKS_FILE.exists() else {}


def load_sharing():
    return json.loads(SHARING_FILE.read_text()) if SHARING_FILE.exists() else None


def describe(a):
    """One assignment as a reader would say it: (how text, level)."""
    via, thr = a.get('via') or {}, a.get('through') or {}
    kinds = {'entraGroup': 'Entra group', 'm365Group': 'Microsoft 365 group', 'directoryRole': 'directory role'}
    t = ''
    if thr.get('title') or thr.get('objectId'):
        nm = (ROLE_NAMES.get(thr.get('objectId')) if thr.get('kind') == 'directoryRole' else None) or thr.get('title') or thr.get('objectId')
        k = kinds.get(thr.get('kind'), thr.get('kind') or 'group')
        if thr.get('kind') == 'm365Group' and thr.get('claimType'):
            k += f" ({thr['claimType']})"
        t = f'{k} {nm}'
        path = [p.get('title') or p.get('objectId') for p in (a.get('path') or []) if p]
        if path:
            t += ', by way of ' + ' > '.join(path)
    how = a.get('how')
    if how == 'siteAdmin':
        text = 'Site collection administrator' + (f', as a member of {t}' if t else '')
    elif how == 'sharePointGroup':
        grp = via.get('title') or via.get('siteGroupId')
        text = (f'Sharing link group {grp}' if via.get('isSharingLink') else f'SharePoint group {grp}') + (f', as a member of {t}' if t else '')
    elif how == 'direct':
        text = f'Member of {t}, which is granted directly' if t else 'Granted directly'
    else:
        text = how or 'unknown'
    return text, (a.get('level') or 'unknown level')


# ---------- levels: what a permission level allows, from the rights it carries ----------

KEY_RIGHTS = {'ManagePermissions': 'manage', 'AddListItems': 'add', 'EditListItems': 'edit', 'DeleteListItems': 'delete',
              'ViewListItems': 'view', 'OpenItems': 'open'}
_FULL = frozenset(KEY_RIGHTS.values())
_EDIT = frozenset({'add', 'edit', 'delete', 'view', 'open'})
_READ = frozenset({'view', 'open'})
# Microsoft's default levels (learn.microsoft.com/sharepoint/understanding-permission-levels), by the rights that decide
# what a person can do with files. A site owner can change every one except Full Control, so the name alone proves nothing.
DEFAULT_LEVELS = {'Full Control': _FULL, 'Manage Hierarchy': _FULL, 'Design': _EDIT, 'Edit': _EDIT, 'Contribute': _EDIT,
                  'Approve': _EDIT, 'Read': _READ, 'Restricted Read': _READ, 'View Only': frozenset({'view'})}
# Levels SharePoint makes itself beyond the defaults above (its Limited Access family and feature levels)
SHAREPOINT_LEVELS = {'Limited Access', 'Web-Only Limited Access', 'Restricted View', 'Review', 'Restricted Interfaces for Translation'}
TIER_NAMES = {3: 'Full control', 2: 'Can edit', 1: 'Can view', 0: 'Level not known'}
TIER_DESC = {3: 'Manage the content, settings and who has access', 2: 'Add, change and delete files',
             1: 'View and download files', 0: 'No rights are listed for this level'}
TIER_VERB = {3: 'has full control', 2: 'can edit', 1: 'can view', 0: 'has access'}


def rights_of(perms):
    return frozenset(KEY_RIGHTS[p] for p in perms or () if p in KEY_RIGHTS)


def tier_of(rights):
    """3 can change who has access, 2 can change files, 1 can view, 0 not known."""
    if 'manage' in rights:
        return 3
    if rights & {'add', 'edit', 'delete'}:
        return 2
    return 1 if rights & {'view', 'open'} else 0


def _join(words, last='and'):
    words = list(words)
    return f' {last} '.join(words) if len(words) < 3 else ', '.join(words[:-1]) + f' {last} ' + words[-1]


def level_note(name, perms):
    """What to say beside a level whose name doesn't tell the whole story: custom, changed from the default, or unlisted."""
    perms = {x for x in perms if not x.startswith('~')}  # '~level' is the server's access level, kept for the tier only
    if not perms - {'?'}:
        return 'rights not listed' if '?' in perms else 'allows nothing'
    rights = rights_of(perms)
    t, words = tier_of(rights), None
    if t == 2 and not {'add', 'edit', 'delete'} <= rights:
        pairs = (('add', 'add'), ('edit', 'change'), ('delete', 'delete'))
        words = (f"can {_join(w for k, w in pairs if k in rights)}, "
                 f"cannot {_join((w for k, w in pairs if k not in rights), 'or')}")
    elif t == 1 and 'open' not in rights:
        words = 'view in the browser, no download'
    elif t == 0:
        words = 'no right to open files'
    std = DEFAULT_LEVELS.get(name)
    if name in SHAREPOINT_LEVELS:  # SharePoint's own, with no fixed rights to compare against
        return words
    if std is None:
        return 'custom level' + (f': {words}' if words else '')
    if rights != std:
        return "changed from SharePoint's default" + (f': {words}' if words else '')
    return None


ACCESS_TIER = {'fullControl': 3, 'write': 2, 'read': 1, 'none': 0}  # the server's access levels on the report's tiers


def tier_for(perms):
    """The tier of a level from its rights. Where the rights are not known ('?'), the server's access level stands in:
    normalize() leaves it as a '~level' marker beside the '?'."""
    t = tier_of(rights_of(perms))
    if '?' in perms:
        t = max([t] + [ACCESS_TIER.get(p[1:], 0) for p in perms if p.startswith('~')])
    return t


def normalize(d):
    """Give every grant entry `level` and `permissions`, whichever shape the pull has, and check the tiers.

    Until MCP knowledge 2026-11-23.1 an entry carried both. Since then it carries roleDefinitionName, roleDefinitionId and
    roleDefinitionAccessLevel, and the rights are on the definitions[] entry with that id in the sharepoint-permission-levels
    record the grant names (roleDefinitionDocumentId). A siteAdmin entry is bound to no level: it gets the rights of the
    record's Full Control level. `permissions` stays None where the rights can't be found, as it was when SharePoint
    returned no level, and the report then says so and takes the tier from the server's access level.
    Safe to call twice: a file that already has _meta.levelChecks is returned as it is."""
    meta = d.setdefault('_meta', {})
    if 'levelChecks' in meta:
        return d
    entries = [(g, a) for g in d.get('grants', []) for a in g.get('assignments') or []]
    if not any('roleDefinitionName' in a or 'roleDefinitionAccessLevel' in a for _, a in entries):
        meta['levelChecks'] = {'shape': 'level and permissions on each entry (before knowledge 2026-11-23.1)'}
        return d
    defs = {rec['id']: {x.get('id'): x for x in rec.get('definitions') or []} for rec in d.get('levels', [])}
    full = {doc: next((x for x in by_id.values() if (x.get('basePermissions') or {}).get('isFullMask')), None)
            or next((x for x in by_id.values() if x.get('name') == 'Full Control'), None) for doc, by_id in defs.items()}
    stats = {'shape': 'roleDefinitionName with rights joined from sharepoint-permission-levels (knowledge 2026-11-23.1)',
             'entries': 0, 'joined': 0, 'siteAdmin': 0, 'noLevelId': 0, 'noLevelsRecord': 0, 'levelNotInRecord': 0,
             'nameDiffers': 0, 'tierDiffers': {}}
    for g, a in entries:
        if 'permissions' in a and 'level' in a:
            continue
        stats['entries'] += 1
        doc, rid, perms = g.get('roleDefinitionDocumentId'), a.get('roleDefinitionId'), None
        a['level'] = a.get('roleDefinitionName')
        if a.get('how') == 'siteAdmin':
            stats['siteAdmin'] += 1
            top = full.get(doc)
            perms = list((top.get('basePermissions') or {}).get('permissions') or []) if top else list(KEY_RIGHTS)
        elif rid is None:
            stats['noLevelId'] += 1
        elif doc not in defs:
            stats['noLevelsRecord'] += 1
        elif rid not in defs[doc]:
            stats['levelNotInRecord'] += 1
        else:
            level = defs[doc][rid]
            perms = list((level.get('basePermissions') or {}).get('permissions') or [])
            stats['joined'] += 1
            if level.get('name') != a.get('roleDefinitionName'):
                stats['nameDiffers'] += 1
        a['permissions'] = perms
        theirs = ACCESS_TIER.get(a.get('roleDefinitionAccessLevel'))
        if perms is not None and theirs is not None and tier_of(rights_of(perms)) != theirs:
            key = f"{a.get('level')}: report tier {TIER_NAMES[tier_of(rights_of(perms))]}, server {a.get('roleDefinitionAccessLevel')}"
            stats['tierDiffers'][key] = stats['tierDiffers'].get(key, 0) + 1
    meta['levelChecks'] = stats
    return d


PERMISSIONS_STEP = 'EnrichSharepointSitePermissions'  # the collection step that reads SharePoint permissions


def latest_run_note(d):
    """A sentence on whether the latest collection run read SharePoint permissions; '' when the pull has no run record.
    A run that didn't read them leaves the earlier records in place, so each site's own date says how old its rows are."""
    runs = d.get('latestRun') or []
    if not runs:
        return ''
    run = runs[0]
    when = (run.get('completedAt') or run.get('startedAt') or '')[:16].replace('T', ' ')
    steps = dict(zip(run.get('nodes[].name') or [], run.get('nodes[].status') or []))
    status = steps.get(PERMISSIONS_STEP)
    if status == 'Succeeded':
        return f' The latest collection run, finished {when} UTC, read SharePoint permissions.'
    how = 'did not include the step that reads SharePoint permissions' if status is None else f'did not finish reading SharePoint permissions (step {status})'
    return (f' The latest collection run, finished {when} UTC, {how}, so the access shown is from an earlier run: '
            "each site's Read date says when.")


def special_family(g):
    """org: Everyone except external users. everyone: Everyone and the all-users claims. app. claim: anything else."""
    kind, login, title = g.get('principalKind'), (g.get('loginName') or '').lower(), (g.get('title') or '').lower()
    if kind == 'everyoneExceptExternal':
        return 'org'
    if kind == 'everyone':
        return 'everyone'
    if kind == 'application':
        return 'app'
    if login.startswith('c:0!.s|') or 'authenticated users' in title or title.startswith('all users'):
        return 'everyone'  # All Users and all authenticated users reach the same accounts as Everyone
    return 'claim'


class Model:
    def __init__(self, d):
        self.d = d
        self.sites = {s['id']: s for s in d['sites']}
        self.secs = {s['id']: s for s in d['securables']}
        self.groups = {g['id']: g for g in d['siteGroups']}
        self.users = {u['id']: u for u in d['users']}
        ROLE_NAMES.update({r['id']: r.get('displayName') for r in d.get('directoryRoles', []) if r.get('displayName')})
        self.grants = defaultdict(list)
        for g in d['grants']:
            self.grants[g['securableId']].append(g)
        self.by_site = defaultdict(list)
        for s in d['securables']:
            self.by_site[s.get('siteId')].append(s)
        self.members_enabled = sum(1 for u in d['users'] if u.get('userType') == 'Member' and u.get('accountEnabled'))
        self.members_all = sum(1 for u in d['users'] if u.get('userType') == 'Member')
        self.people_reg, self.group_reg, self._rows = {}, {}, {}
        # role assignments as SharePoint holds them, for the groups that hold a level and no one
        for r in d.get('roleAssignments', []):
            if r.get('id') in self.secs:
                self.secs[r['id']]['roleAssignments'] = r.get('roleAssignments')
        self.has_role_assignments = bool(d.get('roleAssignments'))
        self.site_groups = defaultdict(dict)
        for g in d['siteGroups']:
            self.site_groups[g.get('siteId')][g.get('title')] = g
        self.level_defs = {}  # (siteId, webId of a subsite with levels of its own, else None) -> level id -> definition
        for rec in d.get('levels', []):
            self.level_defs[(rec.get('siteId'), rec.get('webId') if rec.get('isSubsite') else None)] = {
                x.get('id'): x for x in rec.get('definitions') or []}
        self.sharing, self._inside = load_sharing(), None
        links = load_links()
        self.team_urls = {}
        for team in links.get('teams', []):  # the General channel's link opens the team; else its first standard channel
            chans = list(zip(team.get('channels[].displayName') or [], team.get('channels[].membershipType') or [],
                             team.get('channels[].createdDateTime') or [], team.get('channels[].webUrl') or []))
            pick = [c for c in chans if c[0] == 'General' and c[3]] or sorted((c for c in chans if c[1] == 'standard' and c[3]),
                                                                            key=lambda c: c[2] or '')
            if pick:
                self.team_urls[team['id']] = pick[0][3]
        self.prod_site_ids = {(r.get('webUrl') or '').rstrip('/').lower(): r['id'] for r in links.get('prodSites', [])}
        self.group_names = {g['id']: g.get('displayName') for g in d.get('groupInfo', []) if g.get('displayName')}
        self.group_vis = {g['id']: g.get('visibility') for g in d.get('groupInfo', [])}
        for s in d['sites']:
            if s.get('entraGroup.id') and s.get('entraGroup.displayName'):
                self.group_names.setdefault(s['entraGroup.id'], s['entraGroup.displayName'])

    def root(self, site_id):
        roots = [s for s in self.by_site.get(site_id, []) if s.get('isRootWeb')]
        return roots[0] if roots else None

    def site_kind(self, site):
        """teams, channel, archived, group (no team), orphanGroup, communication or other."""
        r = self.root(site['id'])
        tpl = ((r or {}).get('webTemplate') or '').upper()
        rwt = (site.get('usageReport.rootWebTemplate') or '')
        team_sites = {t.get('sharepointSite.siteId') for t in self.d.get('teams', [])}
        if site.get('entraGroup.isTeamsConnected') is True or site['id'] in team_sites:
            return 'teams'
        if tpl.startswith('TEAMCHANNEL') or 'channel' in rwt.lower():
            return 'channel'
        if (r or {}).get('siteStatus.status') == 'archived':
            return 'archived'
        if site.get('entraGroup.id'):
            return 'group'
        if tpl.startswith('GROUP'):
            return 'orphanGroup'
        if tpl.startswith('SITEPAGEPUBLISHING'):
            return 'communication'
        return 'other'

    def archived_team_name(self, site):
        """An archived site carries no group link, so the only hint it was a Teams site is a team with the same name."""
        return (site.get('displayName') or '').strip() in {(t.get('displayName') or '').strip() for t in self.d.get('teams', [])}

    def effective(self, sec):
        """(securable whose grants apply, inherited?)."""
        if sec.get('hasUniqueRoleAssignments') or sec.get('isRootWeb'):
            return sec, False
        src = self.secs.get(sec.get('inheritsFromId'))
        return src, True

    def access(self, sec):
        """People and other principals with access to a securable with its own permissions."""
        people, others = {}, []
        for g in self.grants.get(sec['id'], []):
            kind = g.get('principalKind')
            if kind == 'system':
                continue
            if kind == 'user':
                key = g.get('principalId') or g.get('nameId') or g.get('userPrincipalName') or g.get('title')
                u = self.users.get(g.get('principalId')) if g.get('principalId') else None
                p = people.setdefault(key, {'name': g.get('title') or (u or {}).get('displayName') or key,
                                            'upn': g.get('userPrincipalName') or (u or {}).get('userPrincipalName') or '',
                                            'external': bool(g.get('isExternal')),
                                            'disabled': (u or {}).get('accountEnabled') is False,
                                            'notInDirectory': g.get('hasUserDocument') is False,
                                            'ways': [], 'roles': set()})
                for a in g.get('assignments') or []:
                    p['ways'].append(describe(a))
                    p['roles'].add(self.role_of(sec, a))
            else:
                ways = [describe(a) for a in g.get('assignments') or []]
                name = (ROLE_NAMES.get(g.get('principalId')) if kind == 'directoryRole' else None) or g.get('title') or g.get('loginName') or kind
                others.append({'kind': kind, 'name': name,
                               'expansion': g.get('expansion'), 'memberCount': g.get('memberCount'),
                               'claimType': g.get('claimType'), 'ways': ways})
        return people, others

    def role_of(self, sec, a):
        if a.get('how') == 'siteAdmin':
            return 'admin'
        via = a.get('via') or {}
        if a.get('how') == 'sharePointGroup':
            g = self.groups.get(via.get('siteGroupId'))
            role = (g or {}).get('role') or via.get('siteGroupRole')  # the entry says it too since knowledge 2026-11-23.1
            if role in ('owners', 'members', 'visitors'):
                return role
            return 'sharing' if via.get('isSharingLink') else 'spgroup'
        return 'direct'

    # ----- access as SharePoint grants it: rows of grants, each group's people kept once -----

    def _person(self, g):
        key = g.get('principalId') or g.get('nameId') or g.get('userPrincipalName') or g.get('title')
        if key not in self.people_reg:
            u = self.users.get(g.get('principalId')) if g.get('principalId') else None
            self.people_reg[key] = {'name': g.get('title') or (u or {}).get('displayName') or key,
                                    'upn': g.get('userPrincipalName') or (u or {}).get('userPrincipalName') or '',
                                    'external': bool(g.get('isExternal')),
                                    'disabled': (u or {}).get('accountEnabled') is False,
                                    'notInDirectory': g.get('hasUserDocument') is False,
                                    'oid': g.get('principalId') if u else None}
        return key

    def _group(self, g):
        """An Entra group, a Microsoft 365 group's members or owners, or a directory role: one entry wherever it is granted."""
        key = (g['principalKind'], g.get('principalId') or g.get('loginName') or g.get('title'), g.get('claimType'))
        info = self.group_reg.get(key)
        if info is None:
            info = self.group_reg[key] = {'kind': g['principalKind'], 'claim': g.get('claimType'), 'id': g.get('principalId'),
                                          'title': g.get('title'), 'name': None, 'members': set(), 'memberCount': 0,
                                          'expansion': g.get('expansion')}
        info['memberCount'] = max(info['memberCount'], g.get('memberCount') or 0)
        if g.get('expansion') == 'unresolved':
            info['expansion'] = 'unresolved'
        return key

    def group_name(self, gk):
        info = self.group_reg[gk]
        if info['kind'] == 'directoryRole':
            return ROLE_NAMES.get(info['id']) or info['title'] or info['id']
        name = info['name'] or self.group_names.get(info['id'])
        if not name:  # SharePoint's own title for a Microsoft 365 group's claim ends in Members or Owners
            name = info['title'] or info['id'] or 'group'
            for suffix in (' Members', ' Owners'):
                if info['kind'] == 'm365Group' and name.endswith(suffix):
                    name = name[:-len(suffix)]
        return name

    def group_prefix(self, gk):
        info = self.group_reg[gk]
        if info['kind'] == 'm365Group':
            return ('owners' if info['claim'] == 'owners' else 'members') + ' of the Microsoft 365 group'
        return 'Microsoft Entra role' if info['kind'] == 'directoryRole' else 'Microsoft Entra group'

    def group_label(self, gk):
        return f'{self.group_prefix(gk)} {self.group_name(gk)}'

    def rows(self, sec):
        """A web's or library's own access as SharePoint grants it: one row per SharePoint group, one for site admins and
        one per level granted directly. Returns {'rows', 'people' (key -> tier and levels), 'special' (org and everyone
        rows), 'unknown' (groups whose members Inspect 365 doesn't know), 'partial'}."""
        if sec['id'] in self._rows:
            return self._rows[sec['id']]
        recs = [g for g in self.grants.get(sec['id'], []) if g.get('principalKind') != 'system']
        by_id = {g['id']: g for g in recs}
        buckets, titles, via_roles = defaultdict(dict), {}, {}
        for g in recs:
            for a in g.get('assignments') or []:
                how, via = a.get('how'), a.get('via') or {}
                target = (('admin',) if how == 'siteAdmin' else
                          ('sp', via.get('siteGroupId') or via.get('title')) if how == 'sharePointGroup' else ('direct',))
                titles[target] = via.get('title')
                via_roles[target] = via.get('siteGroupRole')
                src = a.get('expandedFrom') if a.get('expandedFrom') in by_id else None
                if src and (a.get('through') or {}).get('title') and by_id[src].get('principalKind') != 'directoryRole':
                    self.group_reg[self._group(by_id[src])]['name'] = a['through']['title']  # the directory's current name
                # permissions is null when SharePoint did not return the level, and empty when the level allows nothing
                unknown_rights = ['?'] + ([f"~{a['roleDefinitionAccessLevel']}"] if a.get('roleDefinitionAccessLevel') else [])
                buckets[(g['id'], target, src)].setdefault(a.get('level') or 'unknown level', set()).update(
                    unknown_rights if a.get('permissions') is None else a['permissions'])
        rows = {}
        for (gid, target, src), levels in buckets.items():
            g = by_id[gid]
            key = target if target[0] != 'direct' else ('direct', tuple(sorted(levels)))
            r = rows.get(key)
            if r is None:
                r = rows[key] = {'key': key, 'kind': target[0], 'title': titles.get(target), 'levels': {}, 'people': set(),
                                 'groups': [], 'specials': []}
            for lv, perms in levels.items():
                r['levels'].setdefault(lv, set()).update(perms)
            kind = g.get('principalKind')
            if kind == 'user':
                pk = self._person(g)
                if src:
                    gk = self._group(by_id[src])
                    self.group_reg[gk]['members'].add(pk)
                    if gk not in r['groups']:
                        r['groups'].append(gk)
                else:
                    r['people'].add(pk)
            elif kind in ('m365Group', 'entraGroup', 'directoryRole'):
                gk = self._group(g)
                if gk not in r['groups']:
                    r['groups'].append(gk)
            else:
                sp = {'family': special_family(g), 'title': g.get('title') or g.get('loginName') or kind}
                if sp not in r['specials']:
                    r['specials'].append(sp)
        people, special, unknown, partial = {}, {'org': [], 'everyone': []}, set(), False
        for r in rows.values():
            names = sorted(r['levels'], key=lambda lv: (-tier_for(r['levels'][lv]), lv))
            r['tier'] = 3 if r['kind'] == 'admin' else tier_for(set().union(*r['levels'].values()))
            r['level'] = ', '.join(names)
            notes = [(f'{lv}: {n}' if len(names) > 1 else n) for lv in names if (n := level_note(lv, r['levels'][lv]))]
            r['note'] = '; '.join(notes) or None
            sg = self.groups.get(r['key'][1]) if r['kind'] == 'sp' else None
            r['name'] = 'Site admins' if r['kind'] == 'admin' else 'Granted directly' if r['kind'] == 'direct' else (r['title'] or (sg or {}).get('title') or 'SharePoint group')
            role = (sg or {}).get('role') or (via_roles.get(r['key']) if r['kind'] == 'sp' else None)
            r['role'] = role if role in ('owners', 'members', 'visitors') else None
            r['partial'] = bool(sg and sg.get('membersTruncated'))
            r['groups'].sort(key=lambda gk: self.group_label(gk).lower())
            r['unknown'] = [gk for gk in r['groups'] if self.group_reg[gk]['expansion'] == 'unresolved']
            r['all'] = set(r['people']).union(*(self.group_reg[gk]['members'] for gk in r['groups']))
            partial = partial or r['partial']
            unknown.update(r['unknown'])
            for fam in special:
                if any(sp['family'] == fam for sp in r['specials']):
                    special[fam].append(r)
            for pk in r['all']:
                p = people.setdefault(pk, {'tier': 0, 'levels': set()})
                p['tier'] = max(p['tier'], r['tier'])
                p['levels'].update(names)
        order = sorted(rows.values(), key=lambda r: (-r['tier'], {'sp': 0, 'direct': 1, 'admin': 2}[r['kind']],
                                                     {'owners': 0, 'members': 1, 'visitors': 2}.get(r['role'], 3), (r['name'] or '').lower()))
        self._rows[sec['id']] = acc = {'rows': order, 'people': people, 'special': special, 'unknown': len(unknown), 'partial': partial}
        return acc

    def empty_groups(self, sec):
        """SharePoint groups that are granted a level on a web or library with its own permissions and bring no one in.
        A grant record needs a principal to reach, so such a group has none and only the web's or library's own role
        assignments show it. It matters because anyone added to the group gets that level here. Hidden levels (Limited
        Access) are not access to the web or library, so a group that holds only those is left out, which also leaves
        out sharing-link and Limited Access system groups. Returns rows shaped like rows()' rows, with 'empty' set, 'members'
        holding the group's own member count, and 'system' naming SharePoint's own accounts in it: System Account is the
        only member of some Owners groups, and it is not a person, so such a group brings no one in."""
        have = {r['name'] for r in self.rows(sec)['rows'] if r['kind'] == 'sp'}
        defs = (self.level_defs.get((sec.get('siteId'), sec.get('webId'))) or self.level_defs.get((sec.get('siteId'), None)) or {})
        out = []
        for ra in sec.get('roleAssignments') or []:
            shown = [x for x in ra.get('roleDefinitions') or [] if not x.get('hidden')]
            if ra.get('principalType') != 8 or not shown or ra.get('title') in have:
                continue
            sg = self.site_groups[sec.get('siteId')].get(ra.get('title')) or {}
            system = sorted({g.get('title') or g.get('loginName') or 'a system account' for g in self.grants.get(sec['id'], [])
                             if g.get('principalKind') == 'system'
                             and any((a.get('via') or {}).get('title') == ra.get('title') for a in g.get('assignments') or [])})
            levels = {x.get('name') or 'unknown level': (set((defs[x['id']].get('basePermissions') or {}).get('permissions') or [])
                                                         if x.get('id') in defs else {'?'}) for x in shown}
            names = sorted(levels, key=lambda lv: (-tier_for(levels[lv]), lv))
            notes = [(f'{lv}: {n}' if len(names) > 1 else n) for lv in names if (n := level_note(lv, levels[lv]))]
            out.append({'kind': 'sp', 'role': sg.get('role') if sg.get('role') in ('owners', 'members', 'visitors') else None,
                        'name': ra.get('title'), 'level': ', '.join(names), 'note': '; '.join(notes) or None,
                        'tier': tier_for(set().union(*levels.values())), 'people': set(), 'groups': [], 'specials': [],
                        'all': set(), 'unknown': [], 'partial': False, 'empty': True, 'members': sg.get('memberCount') or 0,
                        'system': system})
        return sorted(out, key=lambda r: (-r['tier'], {'owners': 0, 'members': 1, 'visitors': 2}.get(r['role'], 3), (r['name'] or '').lower()))

    def count_text(self, acc, short=False):
        """Who can open it, as a count: Everyone in the organization first, then named people, then what the number hides."""
        named = len(acc['people'])
        n = f'{named:,}'
        if short:
            lead = f'Everyone ({self.members_enabled:,})' if acc['special']['org'] else 'Everyone' if acc['special']['everyone'] else ''
            if lead:
                return lead + (f' and {n} named' if named else '')
            return ('at least ' if acc['partial'] else '') + f"{n} {'person' if named == 1 else 'people'}"
        people = f"{n} named {'person' if named == 1 else 'people'}"
        if acc['special']['org']:
            head = f'Everyone in the organization ({self.members_enabled:,} accounts)' + (f' and {people}' if named else '')
        elif acc['special']['everyone']:
            head = 'Everyone' + (f' and {people}' if named else '')
        else:
            head = ('at least ' if acc['partial'] else '') + f"{n} {'person' if named == 1 else 'people'}"
        tail = [f'{c:,} {label}' for c, label in (
            (sum(1 for k in acc['people'] if self.people_reg[k]['disabled']), 'disabled'),
            (sum(1 for k in acc['people'] if self.people_reg[k]['notInDirectory']), 'not in Entra'),
            (acc['unknown'], 'group unknown' if acc['unknown'] == 1 else 'groups unknown')) if c]
        if acc['partial'] and (acc['special']['org'] or acc['special']['everyone']):
            tail.append('a list is partial')
        return ', '.join([head] + tail)

    def inside(self, sec):
        """Not shown in any report; for questions about sharing inside, from a separate sharing pull.
        The signs that something inside a web or library with unique permissions is shared separately.
        Accounts and link claims come from its Limited Access System Group: the list's own for a library, the web's
        own for a subsite, every one in the site for the site. Links for a site are all its sharing-link groups; for a
        library or subsite they are the claims its group holds, by the kind of the link each belongs to.
        None when this was not read."""
        if self._inside is None:
            self._inside = {}
            sh = self.sharing or {}
            groups = defaultdict(dict)
            for g in sh.get('limitedGroups', []):
                groups[g.get('siteId')][g.get('title')] = g
            kind_of = {r.get('sharingLink.linkId'): r.get('sharingLink.kind') for r in sh.get('claimLinks', [])}
            for s in (self.d['securables'] if sh else []):
                if not (s.get('hasUniqueRoleAssignments') or s.get('isRootWeb')):
                    continue
                site_groups = groups.get(s.get('siteId'), {})
                if s.get('kind') == 'library':
                    mine = [site_groups.get('Limited Access System Group For List ' + str(s.get('listId')))]
                elif s.get('isRootWeb'):
                    mine = list(site_groups.values())
                else:
                    mine = [site_groups.get('Limited Access System Group For Web ' + str(s.get('webId')))]
                logins, claims, other, partial = set(), set(), defaultdict(int), False
                for g in filter(None, mine):
                    partial = partial or bool(g.get('membersTruncated'))
                    for kind, login, title in zip(g.get('members[].kind') or [], g.get('members[].loginName') or [], g.get('members[].title') or []):
                        if kind == 'user':
                            if (login or '').lower().startswith('i:0#'):
                                logins.add(login.lower().split('|')[-1])
                        elif (login or '').lower().startswith('c:0u.c|tenant|'):  # a sharing link's claim; named ones give the link id
                            claims.add(title.split('.')[-1] if (title or '').startswith('SLinkClaim.') else login)
                        elif kind != 'system':
                            other[{'everyoneExceptExternal': 'org', 'everyone': 'everyone'}.get(kind, 'group')] += 1
                if s.get('isRootWeb'):  # the site as a whole: every sharing-link group it has
                    links = {k: sh[f'links:{k}'].get(s.get('siteId'), 0) for k in LINK_KINDS}
                else:
                    links = defaultdict(int)
                    for c in claims:  # a claim that can't be tied to its link is left out of every report
                        if kind_of.get(c):
                            links[kind_of[c]] += 1
                self._inside[s['id']] = {'links': {k: n for k, n in links.items() if n}, 'logins': logins, 'org': bool(other['org']),
                                         'everyone': bool(other['everyone']), 'groups': other['group'], 'partial': partial}
        raw = self._inside.get(sec['id'])
        if raw is None:
            return None
        acc = self.rows(sec)
        can = {(self.people_reg[k]['upn'] or '').lower() for k in acc['people']}
        open_to_members = bool(acc['special']['org'] or acc['special']['everyone'])
        guests = {x for x in raw['logins'] if '#ext#' in x}
        extra = {x for x in raw['logins'] if x not in can and not (open_to_members and x not in guests)}
        return {'links': raw['links'], 'linkTotal': sum(raw['links'].values()), 'accounts': len(raw['logins']), 'extra': len(extra),
                'guests': len(guests), 'groups': raw['groups'], 'org': raw['org'], 'everyone': raw['everyone'], 'partial': raw['partial']}

    def connection(self, site, kind):
        """What a site is connected to, in plain words: its category, a label, a detail, 'connected' and 'access'
        sentences, its Teams link, and (for the MSP's copy) its and its group's Inspect 365 links."""
        vis = (self.group_vis.get(site.get('entraGroup.id')) or '').lower()
        gname = site.get('entraGroup.displayName') or self.group_names.get(site.get('entraGroup.id')) or site.get('displayName')
        gid = site.get('entraGroup.id')
        out = {'cat': 'sp', 'label': 'SharePoint only', 'detail': None, 'teams_url': None,
               # the app's own id for the site: the server's id, unless the pull came from another server than the
               # app the links open (then load_links() brings that app's ids by site address, and a site it lacks has no link)
               'site_app': (app_url('sharepoint', self.prod_site_ids.get((site.get('webUrl') or '').rstrip('/').lower(), site['id']))
                            if not self.prod_site_ids or (site.get('webUrl') or '').rstrip('/').lower() in self.prod_site_ids else None),
               'group_app': None}
        if kind == 'teams':
            out.update(cat='teams', label='Teams-connected site', detail=f'{vis.capitalize()} team' if vis else None,
                       connected=f"The team {gname} in Microsoft Teams" + (f" ({vis} team)" if vis else '') + ". This site holds the files of the team's standard channels.",
                       access="Managed in Teams: the team's owners and members are the site's owners and members. People can also be added to the site directly.",
                       teams_url=self.team_urls.get(gid), group_app=app_url('group', gid, 'teams') if gid else None)
        elif kind == 'channel':
            out.update(cat='teams', label='Teams channel site', detail='Private or shared channel',
                       connected="A private or shared channel in Microsoft Teams. This site holds that channel's files.",
                       access="Managed only in Teams: the channel's owners and members are the site's owners and members, and SharePoint shows the site's permissions read-only.")
        elif kind == 'group':
            out.update(cat='group', label='Microsoft 365 group site, not in Teams', detail=f'{vis.capitalize()} group' if vis else None,
                       connected=f"The Microsoft 365 group {gname}" + (f" ({vis})" if vis else '') + ". It has no team in Microsoft Teams.",
                       access="The group's owners and members are the site's owners and members, so access changes when the group changes. People can also be added to the site directly.",
                       group_app=app_url('group', gid) if gid else None)
        elif kind == 'orphanGroup':
            out.update(cat='group', label='Microsoft 365 group site, not in Teams', detail='Group not found',
                       connected="A Microsoft 365 group that isn't in the collected data.",
                       access="The group's owners and members are the site's owners and members, as on any group site. People can also be added to the site directly.")
        else:
            out.update(detail=self.kind_label(site, kind),
                       connected="Not connected to a Microsoft 365 group or to Microsoft Teams.",
                       access="Managed in SharePoint, on the site itself: people get in through its Owners, Members and Visitors groups, or are added directly.")
        return out

    def listed(self, include_teams=False):
        """(sites the report lists, Teams-connected and channel sites left out, archived sites, kind by site id)."""
        sites = sorted(self.d['sites'], key=lambda s: (s.get('displayName') or '').lower())
        kinds = {s['id']: self.site_kind(s) for s in sites}
        out = ('archived',) if include_teams else ('teams', 'channel', 'archived')
        return ([s for s in sites if kinds[s['id']] not in out],
                [] if include_teams else [s for s in sites if kinds[s['id']] in ('teams', 'channel')],
                [s for s in sites if kinds[s['id']] == 'archived'], kinds)

    def is_public(self, site):
        return self.group_vis.get(site.get('entraGroup.id')) == 'Public'

    def kind_label(self, site, kind):
        """The site's kind in Microsoft's names (teams-connected-sites, data-access-governance-site-permissions-report)."""
        vis = (self.group_vis.get(site.get('entraGroup.id')) or '').lower()
        tpl = ((self.root(site['id']) or {}).get('webTemplate') or '').upper()
        if kind == 'teams':
            return 'Teams-connected site' + (f', {vis} team' if vis else '')
        if kind == 'channel':
            return 'Channel site'
        if kind == 'group':
            return f'Team site, {vis} group' if vis else 'Team site, Microsoft 365 group'
        if kind == 'orphanGroup':
            return 'Team site, Microsoft 365 group not found'
        if kind == 'communication':
            return 'Communication site'
        if tpl.startswith('STS'):
            return 'Team site (no Microsoft 365 group)'
        names = {'BDR': 'Document Center', 'CONTENTCTR': 'Content center', 'APPCATALOG': 'App catalog', 'SRCHCEN': 'Search center',
                 'PWA': 'Project Web App site'}
        return next((v for k, v in names.items() if tpl.startswith(k)), None) or site.get('usageReport.rootWebTemplate') or 'Other site'

    def compare_web(self, sec):
        """The web a library or subsite with unique permissions would inherit from if its inheritance were restored."""
        webs = [x for x in self.by_site[sec.get('siteId')] if x.get('kind') == 'web']
        if sec.get('kind') == 'library':
            own = next((w for w in webs if w.get('webId') == sec.get('webId')), None)
        else:
            own = next((w for w in webs if w.get('webId') == sec.get('parentWebId')), None) or self.root(sec.get('siteId'))
        return self.effective(own)[0] if own else None


# ---------- html ----------

# Colours follow DESIGN.md's light document ground: graphite for facts, one warning hue (rust) and it marks only
# unique permissions. Flags such as guest, disabled and unknown are bold graphite.
CSS = """
:root{color-scheme:light;--sheet:#E9EFED;--sheet-hi:#F4F8F7;--paper:#FFFFFF;--band:#DCE5E2;--rule:#C6D2CE;--row:#DCE5E2;
--ink:#0C1514;--mute:#4A5B57;--low:#6B7876;--flag:#A6402E;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--sheet);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55}
a{color:var(--ink)}
.wrap{max-width:1120px;margin:0 auto;padding:0 clamp(16px,4vw,44px)}
header{padding:40px 0 24px;border-bottom:1px solid var(--rule)}
.doc{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:var(--mute)}
h1{font-size:clamp(26px,4vw,38px);line-height:1.05;letter-spacing:-.02em;margin-top:10px}
.lede{color:var(--mute);margin-top:12px;max-width:80ch}
.strip{display:flex;flex-wrap:wrap;margin-top:20px;background:var(--paper);border:1px solid var(--rule);border-radius:2px}
.strip>div{flex:1 1 150px;padding:12px 16px;border-right:1px solid var(--rule)}
.strip>div:last-child{border-right:0}
.fig{font-family:var(--mono);font-size:24px;font-weight:600}
.legend{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:.16em;text-transform:uppercase;color:var(--mute);display:block;margin-top:6px}
section{padding:26px 0;border-bottom:1px solid var(--rule)}
h2{font-size:20px;letter-spacing:-.01em}
h3{font-size:15px;margin:18px 0 6px}
.url{font-family:var(--mono);font-size:11px;color:var(--mute);word-break:break-all}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border:1px solid var(--rule);border-radius:2px;background:var(--sheet-hi);color:var(--mute)}
.chip.uniq{background:var(--paper);color:var(--flag);border-color:var(--flag)}
.chip.mark{background:var(--paper);color:var(--ink);border-color:var(--ink)}
.ic{width:14px;height:14px;flex:none}
.org{margin-top:12px;padding:10px 14px;background:var(--paper);border:1px solid var(--ink);border-radius:2px}
.oh{display:flex;align-items:center;gap:8px;font-weight:700;font-size:14px}
.oh .ic{width:17px;height:17px}
.org p{font-size:12.5px;color:var(--mute);margin-top:4px;max-width:96ch}
.count{font-size:13px;margin-top:12px}
.card{background:var(--paper);border:1px solid var(--rule);border-radius:2px;padding:6px 16px 10px;margin-top:6px;overflow-x:auto}
table{width:100%;border-collapse:collapse;color:var(--ink)}
th{font-family:var(--mono);font-size:8.5px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--mute);text-align:left;padding:8px 10px 6px 0;border-bottom:1px solid var(--ink)}
td{font-size:12.5px;padding:6px 10px 6px 0;border-bottom:1px solid var(--row);vertical-align:top}
tr:last-child td{border-bottom:0}
td.to{font-weight:500;width:27%}
td.lv{width:17%}
th.num,td.num{text-align:right;font-family:var(--mono);white-space:nowrap;width:9%}
.role{display:block;font-family:var(--mono);font-size:8.5px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--mute)}
.sub{display:block;font-size:11px;font-weight:400;color:var(--mute);font-family:var(--mono)}
.way .sub{display:inline;margin-left:4px}
.way{display:block}
.flag{font-family:var(--mono);font-size:8.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--ink);margin-left:6px}
.flag.u{color:var(--flag)}
.note{font-size:12.5px;color:var(--mute);margin-top:6px;max-width:92ch}
.lib{border-top:1px solid var(--row);padding-top:10px;margin-top:14px}
details>summary{cursor:pointer;font-size:12.5px;color:var(--mute)}
.toc{columns:2 280px;margin-top:10px;font-size:13px}
ul.plain{list-style:none;margin-top:6px}
ul.plain li{font-size:12.5px;padding:2px 0}
ul.read li{padding:4px 0;max-width:104ch}
.cols{columns:2 320px}
.conn{margin-top:10px;font-size:12.5px;max-width:104ch}
.conn p{margin-top:2px}
.lk{display:flex;flex-wrap:wrap;gap:4px 16px;margin-top:6px}
.lk a,a.ext{color:#0A6E60}
h4.tg{font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--mute);margin:16px 0 4px}
.grp{padding:9px 0;border-bottom:1px solid var(--row);font-size:13px}
.grp .sub{display:inline;margin-left:6px}
.empty{font-size:12.5px;color:var(--low);font-style:italic}
footer{padding:24px 0 48px;font-size:12px;color:var(--mute)}
"""

ICONS = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>'
         '<symbol id="i-org" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
         '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2"/>'
         '<path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><path d="M10 6h4M10 10h4M10 14h4M10 18h4"/></symbol>'
         '<symbol id="i-broken" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
         '<path d="m18.84 12.25 1.72-1.71a5 5 0 0 0-.12-7.07 5 5 0 0 0-6.95 0l-1.72 1.71"/>'
         '<path d="m5.17 11.75-1.71 1.71a5 5 0 0 0 .12 7.07 5 5 0 0 0 6.95 0l1.71-1.71"/><path d="M8 2v3M2 8h3M16 19v3M19 16h3"/></symbol>'
         '</defs></svg>')
ORG_ICON = '<svg class="ic" aria-hidden="true"><use href="#i-org"/></svg>'
BROKEN_ICON = '<svg class="ic" aria-hidden="true"><use href="#i-broken"/></svg>'
UNIQUE_CHIP = f'<span class="chip uniq">{BROKEN_ICON}Unique permissions: inheritance broken</span>'
INLINE = 12  # a grant that names up to this many people prints them; a longer list is collapsed
ROLE = {'owners': 'Owners', 'members': 'Members', 'visitors': 'Visitors'}
USED = defaultdict(set)  # group -> the webs and libraries of this report that grant it
MSP = False  # the MSP's copy names Inspect 365 and links into it; the client's copy has neither the name nor a link


def e(x):
    return html.escape(str(x if x is not None else ''))


def num(n, one, many=None):
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def anchor(gk):
    return 'grp-' + hashlib.md5(repr(gk).encode()).hexdigest()[:10]


def person_html(m, key):
    p = m.people_reg[key]
    flags = ''.join(f'<span class="flag">{f}</span>' for f, on in
                    (('guest', p['external']), ('disabled', p['disabled']), ('not in Entra', p['notInDirectory'])) if on)
    name = (f'<a class="ext" href="{e(app_url("identity", p["oid"]))}" target="_blank" rel="noopener">{e(p["name"])}</a>'
            if MSP and p.get('oid') else e(p['name']))
    return f'{name}{flags}' + (f'<span class="sub">{e(p["upn"])}</span>' if p['upn'] else '')


def names_html(m, keys):
    items = ''.join(f'<span class="way">{person_html(m, k)}</span>'
                    for k in sorted(keys, key=lambda k: (m.people_reg[k]['name'] or '').lower()))
    if len(keys) <= INLINE:
        return items
    return f'<details><summary>Show the {len(keys):,} people named here</summary>{items}</details>'


def who_cell(m, r, sec_id):
    """Who a grant reaches: Everyone-type principals, each group as one line with its count, then the people named."""
    parts = []
    for sp in r['specials']:
        if sp['family'] == 'org':
            parts.append('<span class="way"><b>Everyone in the organization</b> (above)</span>')
        elif sp['family'] == 'everyone':
            parts.append(f'<span class="way"><b>Everyone</b> (above)<span class="sub">{e(sp["title"])}</span></span>')
        else:
            parts.append(f'<span class="way">{e(sp["title"])}<span class="sub">{"app" if sp["family"] == "app" else "SharePoint claim"}</span></span>')
    for gk in r['groups']:
        info, n = m.group_reg[gk], len(m.group_reg[gk]['members'])
        if info['expansion'] == 'unresolved':
            name, state = e(m.group_name(gk)), '<span class="flag">members unknown</span>'
        elif not n:
            name, state = e(m.group_name(gk)), ' (no members)'
        else:
            USED[gk].add(sec_id)
            name, state = f'<a href="#{anchor(gk)}">{e(m.group_name(gk))}</a>', f' ({n:,})'
        parts.append(f'<span class="way">{e(m.group_prefix(gk))} {name}{state}</span>')
    if r['people']:
        parts.append(names_html(m, r['people']))
    if r['partial']:
        parts.append('<span class="way"><span class="flag" style="margin-left:0">list is partial</span></span>')
    if not parts and r.get('empty'):
        if r.get('system') and r.get('members') == len(r['system']):
            return (f'<span class="empty">No person: its only member is SharePoint\'s own {e(_join(r["system"]))}. '
                    'Anyone added to this group gets this level here.</span>')
        if r.get('members'):
            return (f'<span class="empty">No one this report lists: the group has {num(r["members"], "member")}, none of them a person '
                    'or group. Anyone added to it gets this level here.</span>')
        return '<span class="empty">No one today. Anyone added to this group gets this level here.</span>'
    return ''.join(parts) or '<span class="empty">None.</span>'


def people_cell(r):
    n = len(r['all'])
    if any(sp['family'] in ('org', 'everyone') for sp in r['specials']):
        return 'Everyone' + (f'<span class="sub">and {n:,} named</span>' if n else '')
    return f'{n:,}' + ('+' if r['unknown'] or r['partial'] else '')


def grant_table(m, acc, sec_id, placeholders=()):
    """One row per grant. A site's Owners, Members and Visitors groups come first, then other groups, then site admins."""
    rows = sorted(list(acc['rows']) + list(placeholders),
                  key=lambda r: ({'sp': 0, 'direct': 1, 'admin': 2}[r['kind']], {'owners': 0, 'members': 1, 'visitors': 2}.get(r['role'], 3),
                                 (r['name'] or '').lower()))
    if not rows:
        return '<p class="empty">No one is granted access here.</p>'
    out = ['<table><thead><tr><th>Granted to</th><th>Level</th><th class="num">People</th><th>Who</th></tr></thead><tbody>']
    for r in rows:
        if r['kind'] == 'sp':
            to = (f'<span class="role">{ROLE[r["role"]]}</span>' if r['role'] else '') + f'{e(r["name"])}<span class="sub">SharePoint group</span>'
        else:
            to = e(r['name'])
        lvl = e(r['level']) + (f'<span class="sub">{e(r["note"])}</span>' if r['note'] else '')
        out.append(f'<tr><td class="to">{to}</td><td class="lv">{lvl}</td><td class="num">{people_cell(r)}</td>'
                   f'<td>{who_cell(m, r, sec_id)}</td></tr>')
    out.append('</tbody></table>')
    return ''.join(out)


def banners(m, acc, what, public):
    """Everyone in the organization, and Everyone, said first and in words."""
    out = []
    for fam, head in (('org', 'Everyone in the organization'), ('everyone', 'Everyone')):
        rows = acc['special'][fam]
        if not rows:
            continue
        hows = []
        for r in rows:
            if r['kind'] == 'sp':
                role = {'owners': "the site's Owners group", 'members': "the site's Members group",
                        'visitors': "the site's Visitors group"}.get(r['role'], 'the SharePoint group')
                why = ", where SharePoint puts it on a public Microsoft 365 group's site" if public and fam == 'org' and r['role'] == 'members' else ''
                hows.append(f"in {role}, {r['name']} ({r['level']}){why}")
            elif r['kind'] == 'admin':
                hows.append('a site admin')
            else:
                hows.append(f"granted directly on this {what} ({r['level']})")
        if fam == 'org':
            body = (f"Every member account in {TENANT_NAME}, {m.members_enabled:,} enabled today. No guests. "
                    f"SharePoint's name: Everyone except external users. It is {_join(hows)}.")
        else:
            titles = sorted({sp['title'] for r in rows for sp in r['specials'] if sp['family'] == 'everyone'})
            body = ("Every account in the organization. Guests too, if the tenant gives guests this claim; this report can't see that "
                    f"setting. SharePoint's name: {_join(titles)}. It is {_join(hows)}.")
        out.append(f'<div class="org"><div class="oh">{ORG_ICON}{head} {TIER_VERB[max(r["tier"] for r in rows)]}</div><p>{e(body)}</p></div>')
    return ''.join(out)


def access_block(m, sec, what, public=False, placeholders=()):
    acc = m.rows(sec)
    empties = m.empty_groups(sec)  # they carry their level; a placeholder for the same group says less, so it gives way
    placeholders = empties + [p for p in placeholders if p['name'] not in {r['name'] for r in empties}]
    return (banners(m, acc, what, public) + f'<p class="count">Who can open it: <b>{e(m.count_text(acc))}</b></p>'
            + '<div class="card">' + grant_table(m, acc, sec['id'], placeholders) + '</div>')


def role_placeholders(m, site_id, acc):
    """A site's Owners, Members or Visitors group that holds no one has no grant record; it is still listed, as empty."""
    have = {r['role'] for r in acc['rows'] if r['kind'] == 'sp'}
    return [{'kind': 'sp', 'role': g['role'], 'name': g.get('title'), 'level': '', 'note': None, 'people': set(), 'groups': [],
             'specials': [], 'all': set(), 'unknown': [], 'partial': False}
            for g in m.d['siteGroups'] if g.get('siteId') == site_id and g.get('role') in ROLE and g['role'] not in have]


def conn_block(c, url):
    """What the site is connected to and where its access is managed, with links to the site, Teams and (MSP) Inspect 365."""
    links = [f'<a href="{e(url)}" target="_blank" rel="noopener">Open the site</a>' if url else '',
             f'<a href="{e(c["teams_url"])}" target="_blank" rel="noopener">Open in Teams</a>' if c.get('teams_url') else '',
             f'<a href="{e(c["site_app"])}" target="_blank" rel="noopener">Open in Inspect 365</a>' if MSP and c.get('site_app') else '',
             (f'<a href="{e(c["group_app"])}" target="_blank" rel="noopener">Open the {"team" if c["cat"] == "teams" else "group"} in Inspect 365</a>'
              if MSP and c.get('group_app') else '')]
    return (f'<div class="conn"><p><b>Connected to:</b> {e(c["connected"])}</p><p><b>Access:</b> {e(c["access"])}</p>'
            f'<div class="lk">{"".join(x for x in links if x)}</div></div>')


def build(kinds_wanted=DEFAULT_KINDS, msp=False):
    global MSP
    MSP = msp
    d = load()
    m = Model(d)
    USED.clear()
    for s in d['sites']:  # a site with no display name is named by its type and address
        if not (s.get('displayName') or '').strip():
            path = '/' + (s.get('webUrl') or '').split('.sharepoint.com/', 1)[-1]
            s['displayName'] = f"{s.get('usageReport.rootWebTemplate') or 'Site'} at {path}"
    want = [c for c, _ in CATEGORIES if c in kinds_wanted]
    include_teams = 'teams' in want
    listed, _, archived, kinds = m.listed(True)
    conns = {s['id']: m.connection(s, kinds[s['id']]) for s in d['sites']}
    kept = [s for s in listed if conns[s['id']]['cat'] in want]
    excluded = [s for s in listed if conns[s['id']]['cat'] not in want]
    left_out = [c for c, _ in CATEGORIES if c not in want and any(conns[s['id']]['cat'] == c for s in excluded)]
    order = {c: i for i, (c, _) in enumerate(CATEGORIES)}
    kept.sort(key=lambda s: (order[conns[s['id']]['cat']], (s.get('displayName') or '').lower()))
    sites = d['sites']
    run_times = sorted({(r.get('siteStatus.collectedAt') or '')[:16] for r in d['securables'] if r.get('isRootWeb') and r.get('siteStatus.collectedAt')})
    summary = {'sites': len(sites), 'kept': len(kept), 'excludedTeams': sum(kinds[s['id']] == 'teams' for s in excluded),
               'excludedChannel': sum(kinds[s['id']] == 'channel' for s in excluded), 'libraries': 0, 'ownPermissions': 0,
               'archived': len(archived), 'archivedTeamName': sum(m.archived_team_name(s) for s in archived),
               'noRootWeb': 0, 'failed': 0, 'teamsIncluded': include_teams, 'kinds': want, 'openToEveryoneSites': 0,
               'openToEveryoneLibraries': 0, 'siteRows': []}
    body, toc = [], []
    for s in kept:
        sid = s['id']
        root = m.root(sid)
        name = s.get('displayName') or s.get('name') or s.get('webUrl')
        anchor_id = f"site-{sid[:8]}"
        c = conns[sid]
        chips = [f'<span class="chip mark">{e(c["label"])}</span>'] + ([f'<span class="chip">{e(c["detail"])}</span>'] if c['detail'] else [])
        conn_html = conn_block(c, s.get('webUrl'))
        status = (root or {}).get('siteStatus.status')
        row = {'site': name, 'kind': kinds[sid], 'status': status, 'libraries': 0, 'own': 0}
        parts = [f'<section id="{anchor_id}"><div class="wrap"><h2>{e(name)}</h2><div class="url"><a href="{e(s.get("webUrl"))}" target="_blank" rel="noopener">{e(s.get("webUrl"))}</a></div>']
        if not root:
            summary['noRootWeb'] += 1
            chips.append('<span class="chip mark">Permissions never read</span>')
            parts.append(f'<div class="chips">{"".join(chips)}</div>{conn_html}<p class="note">There is no permission data for this '
                         'site, so who can reach it is unknown, not empty.</p></div></section>')
            body.append(''.join(parts)); toc.append((anchor_id, name, 'unknown', False, 0, c['cat'])); summary['siteRows'].append(row)
            continue
        if status != 'ok':
            summary['failed'] += 1
            label = 'Archived: permissions unknown' if status == 'archived' else f'Read {status}: permissions unknown'
            chips.append(f'<span class="chip mark">{e(label)}</span>')
            parts.append(f'<div class="chips">{"".join(chips)}</div>{conn_html}<p class="note">'
                         + ('The site is archived (Microsoft 365 Archive), so SharePoint lets no one read its permissions. '
                            if status == 'archived' else f'The last read failed: {e(root.get("siteStatus.error"))}. ')
                         + 'Its owners, members and library permissions are unknown, not empty.'
                         + (f' Last read in full: {e(root.get("siteStatus.lastSucceededAt"))}.' if root.get('siteStatus.lastSucceededAt') else '')
                         + '</p></div></section>')
            body.append(''.join(parts)); toc.append((anchor_id, name, status, False, 0, c['cat'])); summary['siteRows'].append(row)
            continue
        chips.append(f'<span class="chip">Read {e((root.get("siteStatus.lastSucceededAt") or "")[:10])}</span>')
        acc = m.rows(root)
        site_open = bool(acc['special']['org'])
        if site_open:
            summary['openToEveryoneSites'] += 1
            chips.append(f'<span class="chip mark">{ORG_ICON}Open to everyone in the organization</span>')
        parts.append(f'<div class="chips">{"".join(chips)}</div>{conn_html}')
        parts.append(access_block(m, root, 'site', m.is_public(s), role_placeholders(m, sid, acc)))
        # webs (root and subsites) and their libraries
        webs = [w for w in m.by_site[sid] if w.get('kind') == 'web']
        libs = [x for x in m.by_site[sid] if x.get('kind') == 'library' and not x.get('isSystemLibrary')]
        sys_libs = [x for x in m.by_site[sid] if x.get('kind') == 'library' and x.get('isSystemLibrary')]
        webs.sort(key=lambda w: (not w.get('isRootWeb'), (w.get('webUrl') or '').lower()))
        for w in webs:
            wl = sorted((x for x in libs if x.get('webId') == w.get('webId')), key=lambda x: (x.get('listTitle') or '').lower())
            if not w.get('isRootWeb'):
                src, inh = m.effective(w)
                parts.append(f'<h3>Subsite: {e(w.get("webTitle"))}</h3><div class="url">{e(w.get("webUrl"))}</div>')
                if inh:
                    parts.append(f'<p class="note">Inherits its permissions from {e((src or {}).get("webTitle") or w.get("inheritsFromUrl"))}.</p>')
                else:
                    parts.append(f'<div class="chips">{UNIQUE_CHIP}</div>'
                                 '<p class="note">Only this subsite\'s own grants are listed.</p>' + access_block(m, w, 'subsite'))
            if not wl:
                if w.get('isRootWeb'):
                    parts.append('<h3>Document libraries</h3><p class="empty">No document libraries other than SharePoint\'s own.</p>')
                continue
            if w.get('isRootWeb'):
                parts.append('<h3>Document libraries</h3>')
            for lib in wl:
                summary['libraries'] += 1; row['libraries'] += 1
                src, inh = m.effective(lib)
                lib_open = bool(src and m.rows(src)['special']['org'])
                summary['openToEveryoneLibraries'] += lib_open
                parts.append(f'<div class="lib"><b>{e(lib.get("listTitle"))}</b>'
                             f'<div class="url">{e(lib.get("listUrl"))}</div>')
                if inh:
                    where = 'the site' if (src or {}).get('isRootWeb') else f'subsite {(src or {}).get("webTitle")}'
                    parts.append(f'<div class="chips"><span class="chip">Inherits from {e(where)}</span>'
                                 + (f'<span class="chip mark">{ORG_ICON}Open to everyone in the organization</span>' if lib_open else '')
                                 + f'</div><p class="note">Same access as {e(where)}: '
                                 + (e(m.count_text(m.rows(src))) if src else 'unknown') + '.</p></div>')
                else:
                    summary['ownPermissions'] += 1; row['own'] += 1
                    parts.append(f'<div class="chips">{UNIQUE_CHIP}'
                                 + (f'<span class="chip mark">{ORG_ICON}Open to everyone in the organization</span>' if lib_open else '')
                                 + '</div><p class="note">Only this library\'s own grants are listed. The site\'s groups appear '
                                 'only where this library grants them access itself.</p>' + access_block(m, lib, 'library') + '</div>')
        if sys_libs:
            parts.append(f'<p class="note">Left out: {len(sys_libs)} libraries SharePoint creates for itself '
                         '(such as Site Assets, Site Pages and Style Library).</p>')
        parts.append('</div></section>')
        body.append(''.join(parts)); toc.append((anchor_id, name, 'ok', site_open, row['own'], c['cat'])); summary['siteRows'].append(row)
    gen = dt.datetime.now(dt.timezone.utc)
    empty_li = ('<li><b>Empty groups</b>: a SharePoint group that is granted a level on a site, subsite or library and has no '
                'members is listed with 0 people, because anyone added to it gets that level there. They are not counted in '
                '"Who can open it".</li>\n' if m.has_role_assignments else '')
    read_at = ', '.join(run_times) or 'at the latest collection'
    built = (f'Built only from Inspect 365 data, read {read_at} UTC. This copy is for the MSP: names and Open in Inspect 365 link '
             'to the site, group, team or person in Inspect 365.' if MSP else f'Built from data collected {read_at} UTC.')
    run_note = latest_run_note(d)
    if run_note:
        print('collection:', run_note.strip())
    sources = ', '.join(['sharepoint-sites', 'sharepoint-securables', 'sharepoint-grants', 'sharepoint-site-groups']
                        + (['sharepoint-permission-levels'] if d.get('levels') else []) + ['users', 'teams', 'groups']
                        + (['directory-roles'] if d.get('directoryRoles') else []))
    from collections import Counter
    # groups: each one once, with its people
    grp = []
    for gk in sorted(USED, key=lambda gk: (m.group_name(gk).lower(), m.group_prefix(gk))):
        info = m.group_reg[gk]
        kind = {'m365Group': f"Microsoft 365 group, {'owners' if info['claim'] == 'owners' else 'members'}",
                'directoryRole': 'Microsoft Entra role', 'entraGroup': 'Microsoft Entra group'}[info['kind']]
        ppl = sorted(info['members'], key=lambda k: (m.people_reg[k]['name'] or '').lower())
        glink = (f' <a class="ext" href="{e(app_url("group", info["id"]))}" target="_blank" rel="noopener">Open in Inspect 365</a>'
                 if MSP and info['kind'] in ('m365Group', 'entraGroup') and info.get('id') else '')
        grp.append(f'<div class="grp" id="{anchor(gk)}"><b>{e(m.group_name(gk))}</b>{glink}'
                   f'<span class="sub">{e(kind)}: {num(len(ppl), "person", "people")}, granted on {num(len(USED[gk]), "site or library", "sites and libraries")} here</span>'
                   f'<details{" open" if len(ppl) <= INLINE else ""}><summary>{"People" if len(ppl) <= INLINE else f"Show the {len(ppl):,} people"}</summary>'
                   f'<ul class="plain cols">{"".join(f"<li>{person_html(m, k)}</li>" for k in ppl)}</ul></details></div>')
    dupes = [n for n, c in Counter((x.get('displayName') or '').strip() for x in archived if m.archived_team_name(x)).items() if c > 1]
    dupe_note = ''.join(f' {Counter((x.get("displayName") or "").strip() for x in archived)[n]} of them are named {e(n)}, so at most one is that team\'s site.' for n in dupes)
    arch_items = ''.join(f'<li>{e(s.get("displayName") or s.get("webUrl"))} <span class="sub" style="display:inline">{e(s.get("webUrl"))}</span>'
                         + ('<span class="flag">same name as a team</span>' if m.archived_team_name(s) else '') + '</li>' for s in archived)
    excl_items = ''.join(f'<li>{e(s.get("displayName") or s.get("webUrl"))} '
                         f'<span class="sub" style="display:inline">{e(conns[s["id"]]["label"])}</span></li>'
                         for s in sorted(excluded, key=lambda s: (order[conns[s['id']]['cat']], (s.get('displayName') or '').lower())))
    left_words = join_and(PLURAL[c] for c in left_out)
    teams_read = (f'{left_words[0].upper() + left_words[1:]} are left out of this report and listed at the end.' if left_out else
                  'Every kind is included here.')
    scope = (('Every SharePoint site' if not left_out else 'The ' + join_and(PLURAL[c] for c in want)) + ', with who each site and each document'
             if want else 'No sites, with who each site and each document')

    def toc_row(a, n, st, everyone, own, cat):
        marks = ('' if st == 'ok' else ' <span class="flag">unknown</span>') + (' <span class="flag">everyone</span>' if everyone else '') \
            + (f' <span class="flag u">{own} unique</span>' if own else '')
        return f'<div><a href="#{a}">{e(n)}</a>{marks}</div>'

    head = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light"><title>SharePoint permissions: {e(TENANT_NAME)}</title><style>{CSS}</style></head><body>{ICONS}
<header><div class="wrap"><div class="doc">SharePoint permissions report</div><h1>{e(TENANT_NAME)}</h1>
<p class="lede">{scope} library is granted to: the group, its permission level and how
many people it brings. Each group's people are listed once, under Groups at the end. A library with unique permissions lists only its own grants.
{e(built)}{e(run_note)}</p>
<div class="strip"><div><div class="fig">{summary['kept']}</div><span class="legend">Sites listed</span></div>
{f'<div><div class="fig">{len(excluded)}</div><span class="legend">{e(left_words)} left out</span></div>' if excluded else ''}
<div><div class="fig">{summary['libraries']}</div><span class="legend">Document libraries</span></div>
<div><div class="fig">{summary['ownPermissions']}</div><span class="legend">With unique permissions</span></div>
<div><div class="fig">{summary['openToEveryoneSites']}</div><span class="legend">Sites open to everyone in the organization</span></div>
<div><div class="fig">{summary['archived'] + summary['noRootWeb'] + summary['failed']}</div><span class="legend">Sites with unknown permissions</span></div></div>
</div></header>
<section><div class="wrap"><h2>How to read this</h2>
<ul class="plain read" style="margin-top:8px">
<li><b>Everyone in the organization</b> is SharePoint's "Everyone except external users": every member account in the tenant ({m.members_enabled:,} enabled today) and no guests. It is shown first on a site or library and counted in every total, not listed person by person. {summary['openToEveryoneSites']} sites and {summary['openToEveryoneLibraries']} document libraries here are open to it. <b>Everyone</b>, and SharePoint's "All users", reaches every account in the organization, and guests too if the tenant gives guests that claim, which this report can't see.</li>
<li><b>Granted to.</b> SharePoint gives access to groups, so each row is one grant: the SharePoint group, its permission level and how many people it brings. The site's <b>Owners, Members and Visitors</b> groups are marked. People named in a group are printed. An Entra or Microsoft 365 group is one line with its count, and its people are listed once under <a href="#groups">Groups</a>. On a Microsoft 365 group's site, the group's owners are the site's owners and site admins, and its members are in the Members group.</li>
<li><b>Site admins</b> (site collection administrators) have Full Control on everything in the site, including libraries with unique permissions.</li>
<li>A library that <b>inherits</b> has the same access as its site (or subsite). A library with <b>unique permissions</b> has had its inheritance broken and lists only its own grants. It started as a copy of the site's permissions: where it kept the site's groups, people added to those groups get in here too, and a group or person added to the site later does not.</li>
<li><b>Levels</b> are SharePoint's permission levels as each site has them: Full Control, Edit, Contribute, Read and others. A custom level, or a default level someone changed, says what it allows.</li>
<li><b>Counts</b> include accounts marked disabled or not in Entra, which can't sign in; the count says how many. Where a group's members aren't known the group is marked "members unknown" and the count is a minimum.</li>
{empty_li}<li><b>What a site is connected to</b> decides where its access is managed, and each site says which, with a link to open it. <b>SharePoint only</b> sites, such as communication sites and team sites with no Microsoft 365 group, are managed in SharePoint, on the site itself, through its Owners, Members and Visitors groups or by adding people directly. A <b>Microsoft 365 group site, not in Teams</b> takes its owners and members from the group, so access changes when the group changes; on a public group's site SharePoint also puts Everyone except external users in the Members group with Edit, unless someone changed it. A <b>Teams-connected site</b> holds a team's files, and its owners and members are the team's, managed in Teams. A <b>Teams channel site</b> holds one private or shared channel's files and can only be managed in Teams. {teams_read} The sites below are grouped the same way. OneDrive is not included.</li>
<li><b>Archived sites</b> keep their permissions, and get them back unchanged if the site is reactivated, but SharePoint lets no one read them while archived, so they are listed as unknown.</li>
<li><b>Not in this report:</b> permissions on individual folders and files, files shared directly with people, sharing links, and restricted access control policies. A folder or file inside a library can be open to more people than the library, or closed to some of them.</li>
</ul><h3>Sites</h3>{''.join(f'<h4 class="tg">{label} ({sum(1 for x in toc if x[5] == cat)})</h4><div class="toc">' + ''.join(toc_row(*x) for x in toc if x[5] == cat) + '</div>' for cat, label in CATEGORIES if any(x[5] == cat for x in toc))}
</div></section>"""
    tail = f"""<section id="groups"><div class="wrap"><h2>Groups</h2>
<p class="note">Every Entra group, Microsoft 365 group and Microsoft Entra role that brings people into a site or library above, once, with its people.</p>
{''.join(grp) or '<p class="empty">No groups.</p>'}</div></section>
<section><div class="wrap"><h2>Archived sites: permissions unknown</h2>
<p class="note">These {len(archived)} sites are archived with Microsoft 365 Archive, so SharePoint lets no one read their permissions, and their
owners, members and libraries are unknown, not empty. The collected data keeps no Microsoft 365 group or team link for an archived site, so it can't
say which were Teams-connected sites. {summary['archivedTeamName']} of them share a name with a team, so most of those probably were.{dupe_note}</p>
<ul class="plain">{arch_items or '<li>None.</li>'}</ul></div></section>
{f'<section><div class="wrap"><h2>Sites left out of this report</h2><p class="note">{e(teams_read)}</p><ul class="plain">{excl_items}</ul></div></section>' if excluded else ''}
<footer><div class="wrap">Source: {'Inspect 365' if MSP else 'collected data'} ({sources}).
Generated {gen:%Y-%m-%d %H:%M} UTC.</div></footer></body></html>"""
    suffix = '' if want == list(DEFAULT_KINDS) else '-with-teams' if want == [c for c, _ in CATEGORIES] else '-' + '-'.join(want)
    out_dir = HERE if HERE != _HOME else DATA  # a caller that points HERE elsewhere (the screenshot build) keeps its folder
    out = out_dir / ('report' + suffix + ('-msp' if msp else '') + '.html')
    out.write_text(head + ''.join(body) + tail)
    if not suffix and not msp:  # the summary other scripts compare against stays the default report's
        (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, ensure_ascii=False))
    checks = d.get('_meta', {}).get('levelChecks') or {}
    if 'entries' in checks and not suffix and not msp:  # a pull of the 2026-11-23.1 shape: how the join to the levels went
        summary['levelChecks'] = checks
        (out_dir / 'summary.json').write_text(json.dumps(summary, indent=1, ensure_ascii=False))
    for key, n in (checks.get('tierDiffers') or {}).items():
        print(f'level check: {key} ({n} entries)')
    for key in ('noLevelId', 'noLevelsRecord', 'levelNotInRecord', 'nameDiffers'):
        if checks.get(key):
            print(f'level check: {key} on {checks[key]} entries')
    print(json.dumps({k: v for k, v in summary.items() if k != 'siteRows'}))
    print('wrote', out.relative_to(REPO) if out.is_relative_to(REPO) else out, f"{out.stat().st_size:,} bytes")
