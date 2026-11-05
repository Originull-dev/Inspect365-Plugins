"""Mailboxes, Teams and SharePoint report recipe, v0.2.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/collaboration_deep_dive/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

<run-dir>/run.json names the tenant and date; <run-dir>/inputs/<id>.json holds the response to each query in
queries.json, saved exactly as returned. The report opens with its working set, the findings and Microsoft Secure Score
for the three services, then has one part each for mailboxes, Teams and SharePoint. Every finding check has a view of
the state it reads across the objects in scope, zero counts included. Users the collected data marks high impact are
named, with the reason, beside the mailboxes, teams and OneDrives the data ties to them. A value a source reports shows
under Microsoft's name for it. Every section works from one collection run. The text is labels, definitions and values:
no summaries, judgments, advice or inferred labels (2026-10-05 and 2026-10-07). Tables that show part of a list
pick their rows by a fixed rule, stated in the panel note. The same inputs always produce the same bytes.
"""
import datetime as dt, pathlib, sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import IMPACT_REASON, Report, esc, iso, n, num, width  # noqa: E402

R = Report(__file__, 'collaboration-deep-dive', '0.2.0', 'Mailboxes, Teams and SharePoint report')
D, fact = R.D, R.fact
GB = 1024 ** 3
SELF = 'NT AUTHORITY\\SELF'
GROUP_MAILBOX = 'GroupMailbox'
TOP_STORAGE = 10          # rows in the largest-storage tables
ROSTER_CAP = 30           # teams shown in the roster table
RECENT_DAYS = 45          # the no-interaction check skips mailboxes created this many days before collection or later

# Age bands in days: (label, first day, last day). Labels use only the edges check_facts.py knows.
INTERACTION_BANDS = [('0 to 7 days', 0, 7), ('8 to 30 days', 8, 30), ('31 to 45 days', 31, 45), ('More than 45 days', 46, 10 ** 6)]
TEAM_BANDS = [('0 to 7 days', 0, 7), ('8 to 30 days', 8, 30), ('31 to 45 days', 31, 45), ('46 to 365 days', 46, 365),
              ('More than 365 days', 366, 10 ** 6)]
# Labels for a missing date, one per field (2026-10-07: never "None on record").
NO_INTERACTION = 'No interaction time recorded'
NO_ACTIVITY = 'No activity recorded'
NO_MODIFIED = 'No modification recorded'

# Microsoft's names for the values the sources report. A table cell shows the name with the source's value beneath it
# (R.state); a bar shows the name and its note lists the source's values (2026-10-07).
MAILBOX_TYPE = {'UserMailbox': 'User mailbox', 'SharedMailbox': 'Shared mailbox', 'GroupMailbox': 'Microsoft 365 group mailbox',
                'RoomMailbox': 'Room mailbox', 'EquipmentMailbox': 'Equipment mailbox', 'SchedulingMailbox': 'Bookings mailbox',
                'LinkedMailbox': 'Linked mailbox', 'LegacyMailbox': 'Legacy mailbox', 'TeamMailbox': 'Site mailbox'}
# channelMembershipType is an evolvable enum: shared is the one member Microsoft lists after the unknownFutureValue
# sentinel, and Graph returns shared only to a caller that sends Prefer: include-unknown-enum-members (Microsoft Learn:
# channel resource type; Best practices for working with Microsoft Graph; checked 2026-10-07). Without the header a shared
# channel reads unknownFutureValue, so that value shows as Shared.
CHANNEL_TYPE = {'standard': 'Standard', 'private': 'Private', 'shared': 'Shared', 'unknownFutureValue': 'Shared'}
CHANNEL_ORDER = ['standard', 'private', 'shared']
VISIBILITY = {'private': 'Private', 'public': 'Public', 'hiddenMembership': 'Hidden membership'}
# Graph siteArchiveStatus, under the archive states Microsoft 365 Archive shows (Learn: Archive states in Microsoft 365 Archive).
ARCHIVE = {'recentlyArchived': 'Recently archived', 'fullyArchived': 'Archived', 'reactivating': 'Reactivating'}
# The usage report's Root Web Template values, under the template names Microsoft Learn uses (SharePoint admin center,
# Microsoft 365 Archive and site template articles, checked 2026-10-07).
TEMPLATE = {'Group': 'Group-connected team site', 'Team Site': 'Team site', 'Site Page Publishing': 'Communication site',
            'Team Channel': 'Channel site', 'Document Center': 'Document center', 'App Catalog Site': 'App catalog site',
            'Enterprise Search Center': 'Enterprise Search Center', 'Project Web App Site': 'Project Web App site'}


# ---------------------------------------------------------------- helpers
def utc(s):
    """A stored date or timestamp as UTC; None for no value or Exchange's 1601-01-01 placeholder."""
    if not s or str(s).startswith('1601'):
        return None
    d = iso(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def band(d, bands, none):
    days = R.age(d)
    if days is None:
        return none
    return next(label for label, lo, hi in bands if lo <= max(days, 0) <= hi)


def named(table, raw):
    """Microsoft's name for a source value, recorded as vocabulary; the value itself when the table has no name for it."""
    return D(table.get(raw, raw))


def bars(counts, of, name=None):
    """One bar per count. name gives the label for a source value (vocabulary); fixed labels pass through as they are."""
    return [{'label': esc(name(k) if name else k), 'value': n(v), 'thin': True, 'pct': width(v, of), 'color': 'var(--series-1)'}
            for k, v in counts.items()]


def values(keys):
    """Source values for a note, as written in the data."""
    return ', '.join(D(k) for k in keys)


def ordered(counter):
    """Counts largest first, then by label."""
    return dict(sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def keep(counter, labels, optional=()):
    """Counts for every label, zeros included, plus optional labels only when they occur."""
    return {k: counter.get(k, 0) for k in labels} | {k: counter[k] for k in optional if counter.get(k)}


def yes_no(v):
    return 'Yes' if v is True else 'No' if v is False else 'No value recorded'


def gb(x):
    return None if x is None else round(float(x), 1)


def gb_text(x):
    return 'No value' if x is None else f'{x:,.1f}'


def zero_panel(kicker, note=None):
    return {'kicker': kicker, 'note': note} if note else {'kicker': kicker}


# ---------------------------------------------------------------- high impact
HI = sorted(R.rows('users_high_impact'), key=lambda u: (str(u.get('displayName') or '').lower(), u['id']))
for u in HI:
    D(u.get('displayName') or '')
    D(u.get('userPrincipalName') or '')
HI_ID = {u['id']: u for u in HI}
HI_UPN = {str(u['userPrincipalName']).lower(): u for u in HI if u.get('userPrincipalName')}
hi_n = fact('highImpact.users', len(HI), 'users_high_impact')
hi_reasons = fact('highImpact.byReason', ordered(Counter(IMPACT_REASON.get(t, t) for u in HI
                                                         for t in set(u.get('system.impactSources[].type') or []))), 'users_high_impact')


def why(u):
    """Why the collected data marks the user high impact, in the product's words for each reason."""
    return D(', '.join(sorted({IMPACT_REASON.get(t, t) for t in u.get('system.impactSources[].type') or []})))


def tag(cell, u):
    """Mark a cell whose object the data ties to a high-impact user, with the reason (2026-10-07)."""
    return dict(cell, status=f'High impact: {why(u)}') if u else cell


# ---------------------------------------------------------------- mailboxes
MB = sorted(R.rows('mailboxes'), key=lambda m: (str(m.get('displayName') or '').lower(), m['id']))
mb_total = fact('mailboxes.total', R.total('mailboxes_by_type'), 'mailboxes_by_type')
by_type = fact('mailboxes.byType', ordered(R.buckets('mailboxes_by_type')), 'mailboxes_by_type')
if dict(Counter(m['recipientTypeDetails'] for m in MB)) != by_type or len(MB) != mb_total:
    sys.exit('mailboxes and mailboxes_by_type disagree; run both again')
for m in MB:
    D(m.get('displayName') or '')
    D(m.get('primarySmtpAddress') or '')
TYPES = [t for t in by_type if t != GROUP_MAILBOX]          # types with an account behind them
MBX = [m for m in MB if m['recipientTypeDetails'] != GROUP_MAILBOX]
mbx_n = fact('mailboxes.withAccount', len(MBX), 'mailboxes')
mb_hi = lambda m: HI_ID.get(m.get('user.id'))
type_name = lambda raw: named(MAILBOX_TYPE, raw)


def type_cell(raw):
    return R.state(MAILBOX_TYPE.get(raw, raw), raw, 'Exchange')


def mailbox_cell(m):
    return tag({'text': m['displayName'], 'sub': m.get('primarySmtpAddress') or ''}, mb_hi(m))


# Shared mailboxes and the account behind them (Shared Mailbox with Enabled User Account; ... With Licensed User Account)
SH = [m for m in MB if m['recipientTypeDetails'] == 'SharedMailbox']


def account_state(m):
    e, lic = m.get('user.accountEnabled'), m.get('user.isLicensed')
    if e is None:
        return 'No account linked'
    return ('Account enabled' if e else 'Account disabled') + (', licensed' if lic else ', not licensed')


SH_STATES = ['Account enabled, licensed', 'Account enabled, not licensed', 'Account disabled, licensed', 'Account disabled, not licensed']
sh_state = fact('mailboxes.shared.accountState', keep(Counter(account_state(m) for m in SH), SH_STATES, ['No account linked']), 'mailboxes')
sh_total = fact('mailboxes.shared.total', len(SH), 'mailboxes')
sh_flag = [m for m in SH if m.get('user.accountEnabled') is True or m.get('user.isLicensed') is True]
fact('mailboxes.shared.enabledOrLicensed', [m['displayName'] for m in sh_flag], 'mailboxes')
sh_enabled = fact('mailboxes.shared.accountEnabled', sum(1 for m in SH if m.get('user.accountEnabled') is True), 'mailboxes')
sh_licensed = fact('mailboxes.shared.licensed', sum(1 for m in SH if m.get('user.isLicensed') is True), 'mailboxes')

# Last interaction, by type (Mailbox with no Interaction in 45+ Days). Group mailboxes are left out: their time advances
# with system processing.
inter = {t: Counter() for t in TYPES}
for m in MBX:
    inter[m['recipientTypeDetails']][band(utc(m.get('mailboxStatistics.lastInteractionTime')), INTERACTION_BANDS, NO_INTERACTION)] += 1
BAND_LABELS = [b[0] for b in INTERACTION_BANDS] + [NO_INTERACTION]
inter = fact('mailboxes.lastInteraction', {t: {b: inter[t].get(b, 0) for b in BAND_LABELS} for t in TYPES}, 'mailboxes')
inter_total = fact('mailboxes.lastInteraction.total', {b: sum(inter[t][b] for t in TYPES) for b in BAND_LABELS}, 'mailboxes')
RECENT = [m for m in MBX if R.age(utc(m.get('whenMailboxCreated'))) is not None and R.age(utc(m.get('whenMailboxCreated'))) <= RECENT_DAYS]
created_recent = fact('mailboxes.withAccount.createdInLast45Days', len(RECENT), 'mailboxes')
created_recent_none = fact('mailboxes.withAccount.createdInLast45Days.noInteractionTime',
                           sum(1 for m in RECENT if utc(m.get('mailboxStatistics.lastInteractionTime')) is None), 'mailboxes')

# Storage against the send and receive quota (Mailbox with 90%+ Storage Quota Used; Over 100% Storage Quota Used).
# usageRatio = mailbox size / ProhibitSendReceiveQuota.
def quota_band(r):
    if r is None:
        return 'No size recorded'
    return 'Under 90% of quota' if r < 0.9 else '90% of quota or more, within quota' if r <= 1 else 'Over quota'


QUOTA_LABELS = ['Under 90% of quota', '90% of quota or more, within quota', 'Over quota']
qb = fact('mailboxes.quotaBands', keep(Counter(quota_band(m.get('usageRatio')) for m in MB), QUOTA_LABELS, ['No size recorded']), 'mailboxes')
quotas = Counter(m.get('prohibitSendReceiveQuotaGB') for m in MB if m.get('prohibitSendReceiveQuotaGB') is not None)
quotas = fact('mailboxes.quotaGB', {f'{q:g}': c for q, c in sorted(quotas.items(), key=lambda kv: (-kv[1], kv[0]))}, 'mailboxes')


def size_gb(m):
    v = m.get('mailboxStatistics.totalItemSizeGB')
    return None if v is None else round(float(v), 2)


def used_pct(m):
    return None if m.get('usageRatio') is None else round(100 * float(m['usageRatio']), 2)


TOP = sorted([m for m in MB if m.get('usageRatio') is not None],
             key=lambda m: (-float(m['usageRatio']), m['displayName'].lower(), m['id']))[:TOP_STORAGE]
fact('mailboxes.topQuotaUse', [{'name': m['displayName'], 'type': D(m['recipientTypeDetails']), 'sizeGB': size_gb(m),
                                'quotaGB': m.get('prohibitSendReceiveQuotaGB'), 'usedPercent': used_pct(m),
                                'highImpact': (mb_hi(m) or {}).get('displayName')} for m in TOP], 'mailboxes + users_high_impact')

# Forwarding to an external domain (Mailbox Forwarding to an External Domain): the aggregate counts it, the list names them
fwd_total = fact('mailboxes.externalForwarding.total', R.total('mailboxes_external_forwarding'), 'mailboxes_external_forwarding')
fact('mailboxes.externalForwarding.byDomain', ordered(R.buckets('mailboxes_external_forwarding')), 'mailboxes_external_forwarding')
smtp_set = [m for m in MB if (m.get('forwardingSmtpAddress') or '') != '']
fwd = sorted([m for m in smtp_set if m.get('forwardsToExternalDomain') is True],
             key=lambda m: (str(m.get('forwardingExternalDomain') or '').lower(), m['displayName'].lower(), m['id']))
if len(fwd) != fwd_total:
    sys.exit('mailboxes and mailboxes_external_forwarding disagree on external forwards; run both again')
fact('mailboxes.externalForwarding.mailboxes', [{'mailbox': m['displayName'], 'domain': D(m.get('forwardingExternalDomain') or ''),
                                                 'alsoDelivers': m.get('deliverToMailboxAndForward'),
                                                 'highImpact': (mb_hi(m) or {}).get('displayName')} for m in fwd], 'mailboxes')
fwd_internal = fact('mailboxes.forwarding.smtpVerifiedDomain', sum(1 for m in smtp_set if m.get('forwardsToExternalDomain') is False), 'mailboxes')
fwd_unclassified = fact('mailboxes.forwarding.smtpNotClassified', sum(1 for m in smtp_set if m.get('forwardsToExternalDomain') is None), 'mailboxes')
fwd_recipient = fact('mailboxes.forwarding.recipientObject', sum(1 for m in MB if (m.get('forwardingAddress') or '') != ''), 'mailboxes')


# Permissions assigned on the mailbox itself: not inherited, not deny, not the owner's NT AUTHORITY\SELF entry
def entries(m):
    cols = [m.get(f'mailboxPermissions[].{k}') or [] for k in ('user', 'accessRights', 'isInherited', 'deny')]
    if len({len(c) for c in cols}) > 1:
        sys.exit(f'mailbox {m["id"]}: mailboxPermissions arrays differ in length')
    for u, rights, inherited, deny in zip(*cols):
        rights = {x.strip() for x in (rights if isinstance(rights, str) else ','.join(rights)).split(',')}
        if u != SELF and inherited is not True and str(deny).lower() != 'true':
            yield u, rights


def full_access(m):
    return sorted({u for u, rights in entries(m) if 'FullAccess' in rights}, key=lambda u: (str(u).lower(), str(u)))


TYPE_GROUP = {'SharedMailbox': 'shared', 'UserMailbox': 'user'}
holders, granted, other_rights = {}, Counter(), 0
for m in MBX:
    full = full_access(m)
    other_rights += sum(1 for u, rights in entries(m) if 'FullAccess' not in rights)
    if full:
        granted[m['recipientTypeDetails']] += 1
    for u in full:
        holders.setdefault(u, Counter())[TYPE_GROUP.get(m['recipientTypeDetails'], 'other')] += 1
granted = fact('mailboxes.fullAccess.mailboxesByType', {t: {'granted': granted.get(t, 0), 'of': by_type[t]} for t in TYPES}, 'mailboxes')
H = sorted(({'holder': D(u), 'mailboxes': sum(c.values()), 'shared': c['shared'], 'user': c['user'], 'other': c['other'],
             'highImpact': (HI_UPN.get(str(u).lower()) or {}).get('displayName')} for u, c in holders.items()),
           key=lambda h: (-h['mailboxes'], h['holder'].lower(), h['holder']))
fact('mailboxes.fullAccess.holders', H, 'mailboxes + users_high_impact')
H_shown = [h for h in H if h['mailboxes'] > 1]
h_single = fact('mailboxes.fullAccess.holdersWithOne', len(H) - len(H_shown), 'mailboxes')
h_all = fact('mailboxes.fullAccess.holdersInAll', len(H), 'mailboxes')
h_hi = fact('mailboxes.fullAccess.highImpactHolders', [h['holder'] for h in H if h['highImpact']], 'mailboxes + users_high_impact')
fa_mailboxes = fact('mailboxes.fullAccess.mailboxes', sum(v['granted'] for v in granted.values()), 'mailboxes')
other_rights = fact('mailboxes.permissions.otherDirectRights', other_rights, 'mailboxes')
send_on_behalf = fact('mailboxes.sendOnBehalf', sum(1 for m in MB if str(m.get('grantSendOnBehalfTo') or '').strip() not in ('', '[]')), 'mailboxes')

# The account behind each mailbox and whether another account holds a permission on it (Abandoned Mailbox)
ACCESS = ['Account enabled', 'Account disabled, another account holds a permission', 'Account disabled, no other account holds a permission']


def access_state(m):
    e = m.get('user.accountEnabled')
    if e is None:
        return 'No account linked'
    if e:
        return ACCESS[0]
    return ACCESS[1] if any(True for _ in entries(m)) else ACCESS[2]


acc = {t: Counter(access_state(m) for m in MBX if m['recipientTypeDetails'] == t) for t in TYPES}
ACC_LABELS = ACCESS + (['No account linked'] if any(acc[t]['No account linked'] for t in TYPES) else [])
acc = fact('mailboxes.accountAndPermissions', {t: {k: acc[t].get(k, 0) for k in ACC_LABELS} for t in TYPES}, 'mailboxes')
acc_total = fact('mailboxes.accountAndPermissions.total', {k: sum(acc[t][k] for t in TYPES) for k in ACC_LABELS}, 'mailboxes')

# High-impact users' mailboxes: external forwarding, FullAccess holders and storage (2026-10-07)
HIM = sorted([m for m in MB if m.get('user.id') in HI_ID], key=lambda m: (m['displayName'].lower(), m['id']))


def forwarding(m):
    """The mailbox's forward as the collected data classifies it."""
    if (m.get('forwardingSmtpAddress') or '') != '' and m.get('forwardsToExternalDomain') is True:
        return {'mono': D(m.get('forwardingExternalDomain') or '')}
    other = ([] if (m.get('forwardingSmtpAddress') or '') == '' else
             ['SMTP forward to a verified domain' if m.get('forwardsToExternalDomain') is False else 'SMTP forward, not classified'])
    other += ['Forward to a recipient object'] if (m.get('forwardingAddress') or '') != '' else []
    return {'text': 'No', 'sub': '. '.join(other)} if other else 'No'


him = fact('highImpact.mailboxes', [{'mailbox': m['displayName'], 'type': D(m['recipientTypeDetails']), 'user': mb_hi(m)['displayName'],
                                     'reason': why(mb_hi(m)), 'externalDomain': D(m.get('forwardingExternalDomain') or '')
                                     if m.get('forwardsToExternalDomain') is True and (m.get('forwardingSmtpAddress') or '') != '' else None,
                                     'fullAccess': [D(u) for u in full_access(m)], 'sizeGB': size_gb(m), 'usedPercent': used_pct(m)}
                                    for m in HIM], 'mailboxes + users_high_impact')
hi_no_mailbox = fact('highImpact.withoutMailbox', len(HI) - len({m['user.id'] for m in HIM}), 'mailboxes + users_high_impact')

# ---------------------------------------------------------------- teams
T = sorted(R.rows('teams'), key=lambda t: (t['displayName'].lower(), t['id']))
teams_n = fact('teams.total', R.total('teams'), 'teams')
for t in T:
    D(t['displayName'])


def count_band(v, none, zero, one, more):
    return none if v is None else zero if v == 0 else one if v == 1 else more


owners_band = lambda t: count_band(t.get('summary.ownersCount'), 'No owner count recorded', 'No owner', 'One owner', 'Two or more owners')
members_band = lambda t: count_band(t.get('summary.membersCount'), 'No member count recorded', 'No members', 'One member', 'Two or more members')
guests_band = lambda t: count_band(t.get('summary.guestsCount'), 'No guest count recorded', 'No guests', 'One or more guests', 'One or more guests')
ob = fact('teams.owners', keep(Counter(owners_band(t) for t in T), ['No owner', 'One owner', 'Two or more owners'], ['No owner count recorded']), 'teams')
mbands = fact('teams.members', keep(Counter(members_band(t) for t in T), ['No members', 'One member', 'Two or more members'],
                                    ['No member count recorded']), 'teams')
gbands = fact('teams.guests', keep(Counter(guests_band(t) for t in T), ['No guests', 'One or more guests'], ['No guest count recorded']), 'teams')
guest_seats = fact('teams.guestSeats', sum(t.get('summary.guestsCount') or 0 for t in T), 'teams')
archived = fact('teams.archived', sum(1 for t in T if t.get('isArchived') is True), 'teams')
visibility = fact('teams.visibility', ordered(Counter(D(t.get('visibility') or '') for t in T)), 'teams')
one_or_none = fact('teams.oneOwnerOrNone', ob['No owner'] + ob['One owner'], 'teams')

# Team ownership by high-impact users: the users entity's per-user team roster (teams[].isOwner)
T_IDS = {t['id'] for t in T}
hi_own = {}
for u in HI:
    for tid, own in zip(u.get('teams[].id') or [], u.get('teams[].isOwner') or []):
        if own is True and tid in T_IDS:
            hi_own.setdefault(tid, []).append(u)
fact('teams.highImpactOwners', [{'team': t['displayName'], 'owners': [u['displayName'] for u in hi_own[t['id']]]} for t in T if t['id'] in hi_own],
     'teams + users_high_impact')
hi_teams = fact('teams.withHighImpactOwner', sum(1 for t in T if t['id'] in hi_own), 'teams + users_high_impact')


def hi_owner_cell(t):
    us = hi_own.get(t['id'])
    if not us:
        return 'None'
    return {'text': D(', '.join(u['displayName'] for u in us)), 'sub': D(', '.join(sorted({why(u) for u in us})))}


roster = sorted(T, key=lambda t: (t.get('summary.ownersCount') is None, t.get('summary.ownersCount') or 0,
                                  -(t.get('summary.membersCount') or 0), t['displayName'].lower(), t['id']))[:ROSTER_CAP]


def count_cell(v):
    return 'No count recorded' if v is None else n(v)


roster_rows = fact('teams.roster', [{'team': t['displayName'], 'archived': t.get('isArchived') is True, 'owners': t.get('summary.ownersCount'),
                                     'members': t.get('summary.membersCount'), 'guests': t.get('summary.guestsCount'),
                                     'channels': len(t.get('channels[].id') or []), 'activeChannels': t.get('activeChannels'),
                                     'lastActivity': R.day(utc(t.get('lastActivityDate')), none=NO_ACTIVITY),
                                     'highImpactOwners': [u['displayName'] for u in hi_own.get(t['id'], [])]} for t in roster], 'teams')

act_teams = Counter(band(utc(t.get('lastActivityDate')), TEAM_BANDS, NO_ACTIVITY) for t in T)
act_any = Counter(band(utc(t.get('entityActivity.lastActivityDate')), TEAM_BANDS, NO_ACTIVITY) for t in T)
TB_LABELS = [b[0] for b in TEAM_BANDS] + [NO_ACTIVITY]
act_teams = fact('teams.lastActivity.teams', keep(act_teams, TB_LABELS), 'teams')
act_any = fact('teams.lastActivity.teamsOrSite', keep(act_any, TB_LABELS), 'teams')


# Channels with activity in Microsoft's 90-day Teams activity report (Team with Inactive Channels)
def channel_activity(t):
    ch, a = len(t.get('channels[].id') or []), t.get('activeChannels')
    if a is None:
        return 'Not in the activity report'
    if ch == 0:
        return 'No channels recorded'
    return 'No channel active' if a == 0 else 'Every channel active' if a >= ch else 'Some channels active'


CH_ACT = ['Every channel active', 'Some channels active', 'No channel active']
ch_act = fact('teams.channelActivity', keep(Counter(channel_activity(t) for t in T), CH_ACT,
                                            ['No channels recorded', 'Not in the activity report']), 'teams')
ch_counts = Counter(c for t in T for c in t.get('channels[].membershipType') or [])
ch_teams = Counter(c for t in T for c in set(t.get('channels[].membershipType') or []))
CH_TYPES = CHANNEL_ORDER + sorted(k for k in ch_counts if k not in CHANNEL_ORDER)
channel_types = fact('teams.channels.byMembershipType', {D(k): {'channels': ch_counts.get(k, 0), 'teams': ch_teams.get(k, 0)} for k in CH_TYPES}, 'teams')
channels_n = fact('teams.channels.total', sum(len(t.get('channels[].id') or []) for t in T), 'teams')
if sum(ch_counts.values()) != channels_n:
    sys.exit('teams: channels[].id and channels[].membershipType differ in length')

# ---------------------------------------------------------------- SharePoint
def site_name(s):
    return D(s.get('displayName') or s.get('webUrl') or s['id'])


S = sorted(R.rows('sites'), key=lambda s: (site_name(s).lower(), s['id']))
OD = sorted(R.rows('onedrives'), key=lambda s: (site_name(s).lower(), s['id']))
sites_n = fact('sites.total', R.total('sites'), 'sites')
od_n = fact('onedrives.total', R.total('onedrives'), 'onedrives')


def kind(s):
    if not s.get('entraGroup.id'):
        return 'Not linked to a group'
    return 'Microsoft 365 group, with a team' if s.get('entraGroup.isTeamsConnected') else 'Microsoft 365 group, no team'


KINDS = ['Microsoft 365 group, with a team', 'Microsoft 365 group, no team', 'Not linked to a group']
kinds = fact('sites.byKind', keep(Counter(kind(s) for s in S), KINDS) | {'OneDrive': od_n}, 'sites + onedrives')
all_sites = fact('sites.andOneDrives', sites_n + od_n, 'sites + onedrives')
in_report = lambda s: bool(s.get('usageReport.reportRefreshDate'))
GAPS = ['No template in the report', 'Not in the usage report']


def template(s):
    if not in_report(s):
        return GAPS[1]
    return s['usageReport.rootWebTemplate'] if s.get('usageReport.rootWebTemplate') else GAPS[0]


tpl = Counter(template(s) for s in S)
templates = fact('sites.byTemplate', {D(k): v for k, v in ordered({k: v for k, v in tpl.items() if k not in GAPS}).items()}
                 | {k: tpl[k] for k in GAPS if tpl[k]}, 'sites')
group_tpl_unlinked = fact('sites.groupTemplateNotLinked',
                          sum(1 for s in S if not s.get('entraGroup.id') and s.get('usageReport.rootWebTemplate') == 'Group'), 'sites')
report_date = D(max((s['usageReport.reportRefreshDate'] for s in S if in_report(s)), default=''))


def archive_counts(rows):
    c = Counter(r.get('siteCollection.archivalDetails.archiveStatus') or '' for r in rows)
    return {'Not archived': c.get('', 0)} | ordered({k: v for k, v in c.items() if k})


def archive_cell(raw):
    return R.state(ARCHIVE.get(raw, raw), raw, 'Graph') if raw else 'Not archived'


archive_name = lambda k: k if k == 'Not archived' else named(ARCHIVE, k)
site_arch = fact('sites.archiveStatus', archive_counts(S), 'sites')


# Site activity from Microsoft's SharePoint site usage report (Inactive SharePoint Site)
def activity(s):
    if not in_report(s):
        return 'Not in the usage report'
    if s.get('isInactive') is False:
        return 'Activity in the 90 days before the report date'
    if s.get('isInactive') is True:
        return 'Last activity more than 90 days before the report date' if s.get('lastActivityDate') else NO_ACTIVITY
    return 'Not classified in the report'


ACT_LABELS = ['Activity in the 90 days before the report date', 'Last activity more than 90 days before the report date',
              NO_ACTIVITY, 'Not in the usage report']
site_act = fact('sites.activity', keep(Counter(activity(s) for s in S), ACT_LABELS, ['Not classified in the report']), 'sites')
inactive_n = fact('sites.inactive90', site_act[ACT_LABELS[1]] + site_act[ACT_LABELS[2]], 'sites')
not_in_report = site_act[ACT_LABELS[3]]

# Owners of group-linked sites (Ownerless SharePoint Site; ... with Only One Owner; ... with Orphaned Ownership)
G = [s for s in S if s.get('entraGroup.id')]
groups_n = fact('sites.groupLinked', len(G), 'sites')


def owner_band(k):
    return 'No owner' if k == 0 else 'One owner' if k == 1 else 'Two or more owners'


site_owners = fact('sites.ownersPerGroupSite', keep(Counter(owner_band(len(s.get('owners[].id') or [])) for s in G),
                                                    ['No owner', 'One owner', 'Two or more owners']), 'sites')


def owner_accounts(s):
    if not s.get('owners[].id'):
        return 'No owner'
    if any(d is True for d in s.get('owners[].isDeleted') or []):
        return 'An owner not found in the directory'
    return 'An owner account disabled' if any(e is False for e in s.get('owners[].accountEnabled') or []) else 'No owner disabled or not found'


OWNER_ACCOUNTS = ['No owner disabled or not found', 'An owner account disabled', 'An owner not found in the directory', 'No owner']
site_owner_accounts = fact('sites.ownerAccounts', keep(Counter(owner_accounts(s) for s in G), OWNER_ACCOUNTS), 'sites')
sp_owners = fact('sites.servicePrincipalOwners', sum(1 for s in G for k in s.get('owners[].ownerType') or [] if k == 'servicePrincipal'), 'sites')

largest = sorted([s for s in S if s.get('totalStorageUsedBytes') is not None],
                 key=lambda s: (-s['totalStorageUsedBytes'], site_name(s).lower(), s['id']))[:TOP_STORAGE]


def site_activity_text(s):
    return 'Not in the usage report' if not in_report(s) else R.day(utc(s.get('lastActivityDate')), none=NO_ACTIVITY)


largest = fact('sites.largestByStorage', [{'site': site_name(s), 'kind': kind(s), 'storageGB': gb(s['totalStorageUsedBytes'] / GB),
                                           'files': s.get('fileCount'), 'lastActivity': site_activity_text(s),
                                           'archive': D(s.get('siteCollection.archivalDetails.archiveStatus') or '')} for s in largest], 'sites')


# OneDrives and their owners
def od_owner(o):
    return next((HI_ID[i] for i in o.get('owners[].id') or [] if i in HI_ID), None)


def od_state(o):
    en, de = o.get('owners[].accountEnabled') or [], o.get('owners[].isDeleted') or []
    if not (o.get('owners[].userPrincipalName') or o.get('owners[].id') or en or de):
        return 'No owner recorded'
    if any(d is True for d in de):
        return 'Owner not found in the directory'
    return 'Owner account disabled' if any(e is False for e in en) else 'Owner account enabled'


OD_STATES = ['Owner account enabled', 'Owner account disabled', 'Owner not found in the directory', 'No owner recorded']
od_states = fact('onedrives.ownerState', keep(Counter(od_state(o) for o in OD), OD_STATES), 'onedrives')


def od_row(o):
    last = max((utc(x) for x in o.get('drives[].lastModifiedDateTime') or [] if x), default=None)
    hi = od_owner(o)
    return {'onedrive': site_name(o), 'owner': D(', '.join(o.get('owners[].userPrincipalName') or [])) or 'No owner recorded',
            'storageGB': gb(o['totalStorageUsedBytes'] / GB) if o.get('totalStorageUsedBytes') is not None else None,
            'libraryModified': R.day(last, none=NO_MODIFIED), 'archive': D(o.get('siteCollection.archivalDetails.archiveStatus') or ''),
            'highImpact': hi['displayName'] if hi else None, 'reason': why(hi) if hi else None}


OD_DISABLED = [o for o in OD if od_state(o) in ('Owner account disabled', 'Owner not found in the directory')]
OD_NO_OWNER = [o for o in OD if od_state(o) == 'No owner recorded']
OD_HI = [o for o in OD if od_owner(o)]
od_disabled = fact('onedrives.ownerDisabled', [od_row(o) for o in OD_DISABLED], 'onedrives')
od_no_owner = fact('onedrives.noOwner', [od_row(o) for o in OD_NO_OWNER], 'onedrives')
od_hi = fact('onedrives.highImpactOwner', [od_row(o) for o in OD_HI], 'onedrives + users_high_impact')
od_arch = fact('onedrives.archiveStatus', archive_counts(OD), 'onedrives')

# ---------------------------------------------------------------- opening sections
R.hero(f'Mailboxes, teams, SharePoint sites and OneDrives in the {R.tenant_raw} Microsoft 365 tenant, with the findings and '
       f'Microsoft Secure Score recommended actions for these services, from data collected on {R.as_of}.',
       scope=[('Mailboxes', n(mb_total), 'Every type, group mailboxes included'), ('Teams', n(teams_n)),
              ('SharePoint sites', n(sites_n), 'OneDrives counted separately'), ('OneDrives', n(od_n))])
R.kpis([
    {'kicker': 'Mailboxes forwarding to an external domain', 'value': n(fwd_total), 'unit': f' of {n(mb_total)}',
     'foot': 'SMTP forwarding (forwardingSmtpAddress) to a domain outside the tenant’s verified domains'},
    {'kicker': 'Teams with one owner or no owner', 'value': n(one_or_none), 'unit': f' of {n(teams_n)}',
     'foot': f'One owner: {n(ob["One owner"])}. No owner: {n(ob["No owner"])}'
             + (f'. No owner count recorded: {n(ob["No owner count recorded"])}' if ob.get('No owner count recorded') else '')},
    {'kicker': 'SharePoint sites with no activity in 90 days', 'value': n(inactive_n), 'unit': f' of {n(sites_n)}',
     'foot': 'Microsoft’s SharePoint site usage report (isInactive)' + (f'. Not in the report: {n(not_in_report)}' if not_in_report else '')},
    {'kicker': 'OneDrives whose owner account is disabled', 'value': n(od_states['Owner account disabled']), 'unit': f' of {n(od_n)}',
     'foot': f'Owner not found in the directory: {n(od_states["Owner not found in the directory"])}. '
             f'No owner recorded: {n(od_states["No owner recorded"])}'},
])
R.findings('findings_open', 'findings_accepted', ['Mailbox', 'Team', 'SharePoint'], 'Mailbox, Teams and SharePoint findings')
R.secure_score('secure_score', 'secure_score_controls', 'data',
               'Recommended actions for Exchange Online (EXO), Microsoft Defender for Office 365 (MDO), Microsoft Teams (MS Teams), '
               'SharePoint Online (SPO) and Microsoft Information Protection (MIP) that earn less than their maximum points')
HI_NOTE = ('High impact: a user the collected data marks high impact, for a privileged Entra directory role held directly '
           '(Microsoft’s isPrivileged), for the org chart, or by a technician. ')

# The registry checks each data view shows the state for, named as the registry names them (2026-10-07: a data view
# for every check). The build warns when the registry holds a check of these types that no view names.
CHECK_NAMES = {d['id']: d['displayName'] for d in R.IN['definitions']['definitions'] if d['type'] in ('Mailbox', 'Team', 'SharePoint')}
SHARED_ENABLED, SHARED_LICENSED = '4c97bcf4-8d78-444e-a9e9-c8244a8bddf1', '549ab8b5-d1d9-43b0-a26d-0d5dc0229497'
NO_INTERACTION_CHECK, ABANDONED = '65ebf87d-3d63-4e37-b01e-6041bbd18ef0', 'e30e26ee-4bbb-4a49-ba10-dc2ba981b0dc'
QUOTA_90, QUOTA_100 = '4e96b568-3369-4a52-ae23-a4637a9f171a', '83382223-9747-4456-8b1b-8b88edf3e235'
EXTERNAL_FORWARD = 'a80fffe2-7333-4ae5-aa8b-ad26d661d15a'
TEAM_NO_OWNERS, TEAM_ONE_OWNER, TEAM_NO_MEMBERS = ('9b2f3a17-4c1d-4f8b-9c5e-7a2d8b3c9e10', 'ac9d4e21-5f2b-4a7c-8d6f-1b3e9c4f7a82',
                                                   'c5e9b643-7d4a-4b8e-9f2c-3e6a8b1d4c95')
TEAM_NO_ACTIVITY, TEAM_INACTIVE_CHANNELS = 'bd7e5f32-6a3c-4b8d-9e1f-2c4d5e8f3b91', 'b4d8a3c1-2e9f-4a7b-8c3d-1f5e6a9b0c2d'
SITE_OWNERLESS, SITE_ONE_OWNER = 'f05a9e32-03f8-453c-9c86-9d1ff2444df5', 'aab13446-af8a-4e5d-947a-8d79619f315a'
SITE_ORPHANED, SITE_INACTIVE = '9e24500e-ce36-4282-8e11-0f44edb0a6d2', '295589be-bc42-445e-9574-d5f7f860fcb8'
VIEWED = set()


def checks(*ids):
    """'Check: <name>. ' for the registry checks a view shows."""
    VIEWED.update(ids)
    names = [D(CHECK_NAMES[i]) for i in ids if i in CHECK_NAMES]
    return f'{"Check" if len(names) == 1 else "Checks"}: {"; ".join(names)}. ' if names else ''

# ---------------------------------------------------------------- part 1: mailboxes
R.add({'type': 'parthead', 'kicker': 'Mailboxes', 'title': f'Mailboxes: {n(mb_total)}',
       'sub': 'Exchange Online mailboxes of every type, including the mailboxes of Microsoft 365 groups.'}, 'mailboxes')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'Mailbox types and shared mailbox accounts', 'cols': 2, 'panels': [
    {'kicker': f'Mailboxes by type: {n(mb_total)}', 'bars': bars(by_type, mb_total, type_name),
     'note': f'Exchange’s RecipientTypeDetails, in bar order: {values(by_type)}.'},
    {'kicker': f'Shared mailboxes by the account behind them: {n(sh_total)}', 'bars': bars(sh_state, sh_total),
     'note': checks(SHARED_ENABLED, SHARED_LICENSED) + 'Account enabled is the Entra account’s accountEnabled. Licensed means the '
             'account holds at least one license.'}]}, 'mailbox-types')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': f'Shared mailboxes with an enabled or licensed account: {n(len(sh_flag))}',
       'cols': 1, 'panels': [{
           'cols': [{'key': 'mailbox', 'label': 'Shared mailbox'}, {'key': 'enabled', 'label': 'Account enabled'},
                    {'key': 'licensed', 'label': 'Licensed'}, {'key': 'last', 'label': 'Last interaction'}],
           'rows': [{'mailbox': mailbox_cell(m), 'enabled': yes_no(m.get('user.accountEnabled')), 'licensed': yes_no(m.get('user.isLicensed')),
                     'last': R.day(utc(m.get('mailboxStatistics.lastInteractionTime')), none=NO_INTERACTION)} for m in sh_flag],
           'note': f'Account enabled: {n(sh_enabled)}. Licensed: {n(sh_licensed)}.'} if sh_flag else
           zero_panel(f'Shared mailboxes with an enabled or licensed account: {n(len(sh_flag))} of {n(sh_total)}')]}, 'shared-mailbox-accounts')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'Last interaction by mailbox type', 'cols': 1, 'panels': [{
    'kicker': f'Mailboxes with an account behind them: {n(mbx_n)}',
    'cols': [{'key': 'type', 'label': 'Type'}] + [{'key': f'b{i}', 'label': b, 'n': True} for i, b in enumerate(BAND_LABELS)]
            + [{'key': 'all', 'label': 'Mailboxes', 'n': True}],
    'rows': [{'type': type_cell(t), **{f'b{i}': n(inter[t][b]) for i, b in enumerate(BAND_LABELS)}, 'all': n(by_type[t])} for t in TYPES]
            + [{'type': {'text': 'All'}, **{f'b{i}': n(inter_total[b]) for i, b in enumerate(BAND_LABELS)}, 'all': n(mbx_n)}],
    'note': checks(NO_INTERACTION_CHECK) + f'Days from Exchange’s LastInteractionTime to the collection date. {NO_INTERACTION}: '
            'Exchange reports its placeholder date, 1601-01-01. Group mailboxes are left out: their interaction time advances with system '
            f'processing. Mailboxes created in the last 45 days (WhenMailboxCreated), which the check skips: {n(created_recent)}, '
            f'{n(created_recent_none)} of them with no interaction time recorded.'}]},
      'mailbox-interaction')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'Storage against quota', 'cols': 1, 'panels': [
    {'kicker': f'Mailboxes by share of quota used: {n(mb_total)}', 'bars': bars(qb, mb_total),
     'note': checks(QUOTA_90, QUOTA_100) + 'usageRatio: mailbox size divided by the send and receive quota (ProhibitSendReceiveQuota). Quotas: '
             + ', '.join(f'{q} GB on {n(c)} mailboxes' for q, c in quotas.items()) + '.'},
    {'kicker': f'The {n(len(TOP))} mailboxes using the largest share of their quota',
     'cols': [{'key': 'mailbox', 'label': 'Mailbox'}, {'key': 'type', 'label': 'Type'}, {'key': 'size', 'label': 'Size (GB)', 'n': True},
              {'key': 'quota', 'label': 'Quota (GB)', 'n': True}, {'key': 'used', 'label': 'Quota used', 'n': True}],
     'rows': [{'mailbox': tag({'text': m['displayName']}, mb_hi(m)), 'type': type_cell(m['recipientTypeDetails']),
               'size': 'No value' if size_gb(m) is None else f'{size_gb(m):,.2f}',
               'quota': 'No value' if m.get('prohibitSendReceiveQuotaGB') is None else num(m['prohibitSendReceiveQuotaGB']),
               'used': f'{used_pct(m):,.2f}%'} for m in TOP],
     'note': 'Highest usageRatio first; ties by name. Sizes are Exchange’s TotalItemSize.'}]}, 'mailbox-storage')
fwd_note = (f'SMTP forwards to the tenant’s verified domains: {n(fwd_internal)}. Forwards to a recipient object (forwardingAddress): '
            f'{n(fwd_recipient)}; the collected data does not classify these as internal or external.'
            + (f' SMTP forwards not classified: {n(fwd_unclassified)}.' if fwd_unclassified else '')
            + ' Forwarding by inbox rules and transport rules is not collected.')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'Mail forwarding', 'cols': 1, 'panels': [
    {'kicker': f'Mailboxes forwarding to an external domain: {n(fwd_total)}',
     'cols': [{'key': 'mailbox', 'label': 'Mailbox'}, {'key': 'type', 'label': 'Type'}, {'key': 'domain', 'label': 'Forwards to domain'},
              {'key': 'keep', 'label': 'Also delivers to the mailbox'}],
     'rows': [{'mailbox': mailbox_cell(m), 'type': type_cell(m['recipientTypeDetails']), 'domain': {'mono': D(m.get('forwardingExternalDomain') or '')},
               'keep': {'True': 'Yes', 'False': 'No'}.get(str(m.get('deliverToMailboxAndForward')), 'No value recorded')} for m in fwd],
     'note': checks(EXTERNAL_FORWARD) + 'External: forwardingSmtpAddress is set and its domain is not one of the tenant’s verified '
             'domains (forwardsToExternalDomain). Also delivers is Exchange’s DeliverToMailboxAndForward. ' + fwd_note} if fwd else
    zero_panel(f'Mailboxes forwarding to an external domain: {n(fwd_total)}', checks(EXTERNAL_FORWARD) + fwd_note)]}, 'mail-forwarding')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'FullAccess held by other accounts', 'cols': 1, 'panels': [
    {'kicker': f'Mailboxes where another account holds FullAccess: {n(fa_mailboxes)} of {n(mbx_n)}',
     'bars': [{'label': esc(type_name(t)), 'value': f'{n(v["granted"])} of {n(v["of"])}', 'thin': True, 'pct': width(v['granted'], v['of']),
               'color': 'var(--series-1)'} for t, v in granted.items()],
     'note': 'FullAccess entries assigned on the mailbox itself (mailboxPermissions[], isInherited false), leaving out the owner’s own '
             f'NT AUTHORITY\\SELF entry. Exchange’s RecipientTypeDetails, in bar order: {values(granted)}. Group mailbox permissions are '
             'not collected.'},
    {'kicker': f'Holders with FullAccess on more than one mailbox: {n(len(H_shown))}',
     'cols': [{'key': 'holder', 'label': 'Holder'}, {'key': 'all', 'label': 'Mailboxes', 'n': True}, {'key': 'shared', 'label': 'Shared', 'n': True},
              {'key': 'user', 'label': 'User', 'n': True}, {'key': 'other', 'label': 'Room, equipment or Bookings', 'n': True}],
     'rows': [{'holder': tag({'mono': h['holder']}, HI_UPN.get(h['holder'].lower())), 'all': n(h['mailboxes']), 'shared': n(h['shared']),
               'user': n(h['user']), 'other': n(h['other'])} for h in H_shown],
     'note': f'Most mailboxes first; ties by holder. {HI_NOTE}High-impact holders: {n(len(h_hi))}. Holders with FullAccess on one mailbox: '
             f'{n(h_single)}. Holders in all: {n(h_all)}. Directly assigned rights other than FullAccess: {n(other_rights)}. Send on behalf '
             f'(grantSendOnBehalfTo) is set on {n(send_on_behalf)} mailboxes. Send As permissions are not collected.'} if H_shown else
    zero_panel(f'Holders with FullAccess: {n(h_all)}')]}, 'mailbox-full-access')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': 'Account state and permissions held by other accounts', 'cols': 1, 'panels': [{
    'kicker': f'Mailboxes with an account behind them: {n(mbx_n)}',
    'cols': [{'key': 'type', 'label': 'Type'}] + [{'key': f'a{i}', 'label': k, 'n': True} for i, k in enumerate(ACC_LABELS)]
            + [{'key': 'all', 'label': 'Mailboxes', 'n': True}],
    'rows': [{'type': type_cell(t), **{f'a{i}': n(acc[t][k]) for i, k in enumerate(ACC_LABELS)}, 'all': n(by_type[t])} for t in TYPES]
            + [{'type': {'text': 'All'}, **{f'a{i}': n(acc_total[k]) for i, k in enumerate(ACC_LABELS)}, 'all': n(mbx_n)}],
    'note': checks(ABANDONED) + 'Account: the linked Entra account’s accountEnabled. Permission held by another account: an entry '
            'with any right assigned on the mailbox itself (mailboxPermissions[], isInherited false, not deny) for an account other than '
            'NT AUTHORITY\\SELF. Group mailbox permissions are not collected.'}]}, 'mailbox-accounts')
R.add({'type': 'panels', 'kicker': 'Mailboxes', 'title': f'High-impact users’ mailboxes: {n(len(him))}', 'cols': 1, 'panels': [
    {'kicker': f'High-impact users with a mailbox: {n(len(him))} of {n(hi_n)}',
     'cols': [{'key': 'mailbox', 'label': 'Mailbox'}, {'key': 'type', 'label': 'Type'}, {'key': 'why', 'label': 'High impact'},
              {'key': 'fwd', 'label': 'Forwards to an external domain'}, {'key': 'fa', 'label': 'FullAccess held by'},
              {'key': 'size', 'label': 'Size (GB)', 'n': True}, {'key': 'used', 'label': 'Quota used', 'n': True}],
     'rows': [{'mailbox': {'text': m['displayName'], 'sub': m.get('primarySmtpAddress') or ''}, 'type': type_cell(m['recipientTypeDetails']),
               'why': {'text': why(mb_hi(m))}, 'fwd': forwarding(m),
               'fa': {'text': ', '.join(D(u) for u in full_access(m))} if full_access(m) else 'No other account',
               'size': 'No value' if size_gb(m) is None else f'{size_gb(m):,.2f}',
               'used': 'No value' if used_pct(m) is None else f'{used_pct(m):,.2f}%'} for m in HIM],
     'note': f'{HI_NOTE}High-impact users with no mailbox: {n(hi_no_mailbox)}. FullAccess held by: entries assigned on the '
             'mailbox itself, leaving out NT AUTHORITY\\SELF. Size is Exchange’s TotalItemSize; quota used is usageRatio.'} if HIM else
    zero_panel(f'High-impact users with a mailbox: 0 of {n(hi_n)}', HI_NOTE.strip())]}, 'high-impact-mailboxes')

# ---------------------------------------------------------------- part 2: Teams
R.add({'type': 'parthead', 'kicker': 'Teams', 'title': f'Teams: {n(teams_n)}',
       'sub': 'Teams in Microsoft Teams. Each team belongs to a Microsoft 365 group.'}, 'teams')
R.add({'type': 'panels', 'kicker': 'Teams', 'title': 'Owners, members, guests and visibility', 'cols': 2, 'panels': [
    {'kicker': f'Owners per team: {n(teams_n)} teams', 'bars': bars(ob, teams_n),
     'note': checks(TEAM_NO_OWNERS, TEAM_ONE_OWNER) + 'Microsoft Graph’s summary.ownersCount.'},
    {'kicker': f'Members per team: {n(teams_n)} teams', 'bars': bars(mbands, teams_n),
     'note': checks(TEAM_NO_MEMBERS) + 'Microsoft Graph’s summary.membersCount: every non-guest on the roster, owners included.'},
    {'kicker': f'Guests per team: {n(teams_n)} teams', 'bars': bars(gbands, teams_n),
     'note': f'Guest seats across all teams: {n(guest_seats)} (summary.guestsCount); a guest on two teams counts twice. People added only '
             'to a shared channel are not on the team roster and are not counted.'},
    {'kicker': f'Teams by visibility: {n(teams_n)}', 'bars': bars(visibility, teams_n, lambda k: named(VISIBILITY, k)),
     'note': f'Microsoft Graph’s team visibility, in bar order: {values(visibility)}.'}]}, 'team-membership')
R.add({'type': 'panels', 'kicker': 'Teams', 'title': 'Owners, members, guests and channels by team', 'cols': 1, 'panels': [{
    'cols': [{'key': 'team', 'label': 'Team'}, {'key': 'owners', 'label': 'Owners', 'n': True}, {'key': 'members', 'label': 'Members', 'n': True},
             {'key': 'guests', 'label': 'Guests', 'n': True}, {'key': 'channels', 'label': 'Channels', 'n': True},
             {'key': 'active', 'label': 'Active channels', 'n': True}, {'key': 'last', 'label': 'Last Teams activity'},
             {'key': 'hi', 'label': 'High-impact owners'}],
    'rows': [{'team': {'text': r['team'], 'sub': 'Archived'} if r['archived'] else {'text': r['team']},
              'owners': count_cell(r['owners']), 'members': count_cell(r['members']), 'guests': count_cell(r['guests']),
              'channels': n(r['channels']), 'active': count_cell(r['activeChannels']), 'last': r['lastActivity'],
              'hi': hi_owner_cell(t)} for r, t in zip(roster_rows, roster)],
    'note': ('Fewest owners first, then most members; teams with no counts recorded last. '
             + (f'The first {n(len(roster_rows))} of {n(teams_n)} teams. ' if teams_n > len(roster_rows) else '')
             + f'{HI_NOTE}Teams with a high-impact owner: {n(hi_teams)} of {n(teams_n)}, from the owner role on each user’s team '
             'membership. Active channels: channels with at least one active user in Microsoft’s 90-day Teams activity report '
             f'(activeChannels). Archived: Microsoft’s isArchived, read-only mode; archived teams: {n(archived)}.')}]}, 'team-roster')
R.add({'type': 'panels', 'kicker': 'Teams', 'title': 'Last activity', 'cols': 2, 'panels': [
    {'kicker': f'Last activity in Microsoft Teams: {n(teams_n)} teams', 'bars': bars(act_teams, teams_n),
     'note': 'Days from lastActivityDate in Microsoft’s Teams team activity report to the collection date.'},
    {'kicker': f'Last activity in the team or its SharePoint site: {n(teams_n)} teams', 'bars': bars(act_any, teams_n),
     'note': checks(TEAM_NO_ACTIVITY) + 'The later of the Teams activity date and the site’s SharePoint activity date '
             '(entityActivity.lastActivityDate), the date the check reads.'}]}, 'team-activity')
UNKNOWN_NOTE = (' Graph returns shared only to a caller that asks for evolvable enum members (Prefer: include-unknown-enum-members); '
                'other callers get the unknownFutureValue sentinel, and shared is the only channel type Microsoft lists after it '
                '(Microsoft Learn: channel resource type; Best practices for working with Microsoft Graph).'
                if 'unknownFutureValue' in ch_counts else '')
R.add({'type': 'panels', 'kicker': 'Teams', 'title': 'Channels', 'cols': 2, 'panels': [
    {'kicker': f'Teams by channel activity: {n(teams_n)} teams', 'bars': bars(ch_act, teams_n),
     'note': checks(TEAM_INACTIVE_CHANNELS) + 'Active channels in Microsoft’s 90-day Teams activity report (activeChannels) against '
             'the channels the team has on record. '
             'The report can count more channels than the team has on record; those teams count as every channel active.'},
    {'kicker': f'Channels by membership type: {n(channels_n)}',
     'cols': [{'key': 'type', 'label': 'Membership type'}, {'key': 'channels', 'label': 'Channels', 'n': True},
              {'key': 'teams', 'label': 'Teams with one or more', 'n': True}],
     'rows': [{'type': R.state(CHANNEL_TYPE.get(k, k), k, 'Graph'), 'channels': n(channel_types[k]['channels']),
               'teams': n(channel_types[k]['teams'])} for k in CH_TYPES],
     'note': 'Microsoft Graph’s channel membershipType.' + UNKNOWN_NOTE + ' Channel membership is not collected.'}]}, 'team-channels')

# ---------------------------------------------------------------- part 3: SharePoint
R.add({'type': 'parthead', 'kicker': 'SharePoint', 'title': f'SharePoint: {n(sites_n)} sites and {n(od_n)} OneDrives',
       'sub': 'SharePoint sites, including those behind Microsoft 365 groups and teams, and OneDrive accounts.'}, 'sharepoint')
R.add({'type': 'panels', 'kicker': 'SharePoint', 'title': 'Sites by kind and template', 'cols': 2, 'panels': [
    {'kicker': f'Sites and OneDrives by kind: {n(all_sites)}', 'bars': bars(kinds, all_sites),
     'note': f'Linked to a group: the collected data ties the site to a Microsoft 365 group (entraGroup.id). With a team: the group has a '
             f'team. Sites not linked to a group that use the Group template: {n(group_tpl_unlinked)}.'},
    {'kicker': f'Sites by template: {n(sites_n)}',
     'cols': [{'key': 'tpl', 'label': 'Template'}, {'key': 'sites', 'label': 'Sites', 'n': True}],
     'rows': [{'tpl': {'text': k} if k in GAPS else R.state(TEMPLATE.get(k, k), k, 'Usage report'), 'sites': n(v)} for k, v in templates.items()],
     'note': 'The Root Web Template column of Microsoft’s SharePoint site usage report (rootWebTemplate), under the template names '
             'Microsoft Learn uses.'}]}, 'site-types')
R.add({'type': 'panels', 'kicker': 'SharePoint', 'title': 'Activity and Microsoft 365 Archive', 'cols': 2, 'panels': [
    {'kicker': f'Site activity: {n(sites_n)} sites', 'bars': bars(site_act, sites_n),
     'note': checks(SITE_INACTIVE) + 'From Microsoft’s SharePoint site usage report' + (f', refreshed {esc(report_date)}' if report_date else '')
             + ' (isInactive, lastActivityDate). The check also counts activity in the group’s team. OneDrives are not in the report.'},
    {'kicker': f'Sites by archive status: {n(sites_n)}', 'bars': bars(site_arch, sites_n, archive_name),
     'note': 'Microsoft 365 Archive states from Graph’s siteCollection archivalDetails.archiveStatus'
             + (' (' + ', '.join(f'{archive_name(k)}: {D(k)}' for k in site_arch if k != 'Not archived') + ')' if len(site_arch) > 1 else '')
             + '. A site with no archiveStatus is not archived.'}]},
      'site-activity')
R.add({'type': 'panels', 'kicker': 'SharePoint', 'title': 'Owners of group-linked sites', 'cols': 2, 'panels': [
    {'kicker': f'Owners per group-linked site: {n(groups_n)} sites', 'bars': bars(site_owners, groups_n),
     'note': checks(SITE_OWNERLESS, SITE_ONE_OWNER) + f'Owners of the site’s Microsoft 365 group (owners[]). Service principal owners: '
             f'{n(sp_owners)}.'},
    {'kicker': f'Group-linked sites by owner accounts: {n(groups_n)} sites', 'bars': bars(site_owner_accounts, groups_n),
     'note': checks(SITE_ORPHANED) + 'Disabled: the owner’s Entra account has accountEnabled false. Not found: the owner matches no user in the collected '
             'directory (owners[].isDeleted). Service principal owners have no account state here.'}]}, 'site-owners')
R.add({'type': 'panels', 'kicker': 'SharePoint', 'title': 'Largest sites by storage', 'cols': 1, 'panels': [{
    'kicker': f'The {n(len(largest))} sites using the most storage',
    'cols': [{'key': 'site', 'label': 'Site'}, {'key': 'kind', 'label': 'Kind'}, {'key': 'gb', 'label': 'Storage (GB)', 'n': True},
             {'key': 'files', 'label': 'Files', 'n': True}, {'key': 'last', 'label': 'Last activity'}, {'key': 'arch', 'label': 'Archive status'}],
    'rows': [{'site': {'text': r['site']}, 'kind': esc(r['kind']), 'gb': gb_text(r['storageGB']), 'files': '' if r['files'] is None else n(r['files']),
              'last': esc(r['lastActivity']), 'arch': archive_cell(r['archive'])} for r in largest],
    'note': 'Most storage first; ties by name. Storage is totalStorageUsedBytes, the site collection’s quota.used, which the collected '
            'data rounds to a tenth of a GB. Files is the usage report’s file count. OneDrives are not included.'}]}, 'site-storage')
OD_COLS = [{'key': 'od', 'label': 'OneDrive'}, {'key': 'owner', 'label': 'Owner'}, {'key': 'gb', 'label': 'Storage (GB)', 'n': True},
           {'key': 'mod', 'label': 'Library last modified'}, {'key': 'arch', 'label': 'Archive status'}]


def od_cells(o):
    r = od_row(o)
    return {'od': tag({'text': r['onedrive']}, od_owner(o)), 'owner': {'mono': r['owner']}, 'gb': gb_text(r['storageGB']),
            'mod': r['libraryModified'], 'arch': archive_cell(r['archive'])}


LIB_NOTE = 'Library last modified: the latest lastModifiedDateTime of the OneDrive’s libraries.'
R.add({'type': 'panels', 'kicker': 'SharePoint', 'title': 'OneDrive owners', 'cols': 1, 'panels': [
    {'kicker': f'OneDrives by owner account: {n(od_n)}', 'bars': bars(od_states, od_n),
     'note': 'The owner of the OneDrive library (owners[]), matched to the Entra account. OneDrives in Microsoft 365 Archive: '
             + ', '.join(f'{esc(archive_name(k))} {n(v)}' for k, v in od_arch.items() if k != 'Not archived')
             + (f' (Graph archiveStatus: {values(k for k in od_arch if k != "Not archived")}).' if len(od_arch) > 1 else 'none.')},
    {'kicker': f'OneDrives whose owner account is disabled or not found: {n(len(od_disabled))}', 'cols': OD_COLS,
     'rows': [od_cells(o) for o in OD_DISABLED], 'note': LIB_NOTE} if od_disabled else
    zero_panel(f'OneDrives whose owner account is disabled or not found: {n(len(od_disabled))}'),
    {'kicker': f'OneDrives with no owner recorded: {n(len(od_no_owner))}', 'cols': OD_COLS, 'rows': [od_cells(o) for o in OD_NO_OWNER]}
    if od_no_owner else zero_panel(f'OneDrives with no owner recorded: {n(len(od_no_owner))}'),
    {'kicker': f'High-impact users with a OneDrive: {n(len(od_hi))} of {n(hi_n)}',
     'cols': [{'key': 'od', 'label': 'OneDrive'}, {'key': 'why', 'label': 'High impact'}, {'key': 'gb', 'label': 'Storage (GB)', 'n': True},
              {'key': 'mod', 'label': 'Library last modified'}, {'key': 'arch', 'label': 'Archive status'}],
     'rows': [{'od': {'text': r['onedrive'], 'sub': r['owner']}, 'why': {'text': r['reason']}, 'gb': gb_text(r['storageGB']),
               'mod': r['libraryModified'], 'arch': archive_cell(r['archive'])} for r in od_hi],
     'note': f'{HI_NOTE}{LIB_NOTE}'} if od_hi else zero_panel(f'High-impact users with a OneDrive: 0 of {n(hi_n)}', HI_NOTE.strip())]},
      'onedrive-owners')

# ---------------------------------------------------------------- footer
R.footer(f'Read-only collection on {R.as_of}. Every value comes from a fixed query of one collection run; the same queries run for every tenant.',
         'Open means Needs Review or Flagged. High impact: a user the collected data marks high impact, for a privileged Entra directory '
         'role, the org chart, or a technician’s mark; the report names these users beside the mailboxes, teams and OneDrives the data ties '
         'to them. Last interaction is Exchange’s LastInteractionTime. Team activity comes from Microsoft’s Teams activity report and site '
         'activity from Microsoft’s SharePoint site usage report. A site is linked to a group when the collected data ties it to a '
         'Microsoft 365 group. Names for source values are Microsoft’s, with the source’s value beneath them.',
         'Forwarding by inbox rules or transport rules. Send As permissions. Permissions on group mailboxes. People added only to a shared '
         'channel, and external participants in shared channels. OneDrive activity: OneDrives are not in Microsoft’s site usage report.')
for i in sorted(set(CHECK_NAMES) - VIEWED):
    print(f'warning: the registry check {CHECK_NAMES[i]} ({i}) has no data view in this report', file=sys.stderr)
R.write()
