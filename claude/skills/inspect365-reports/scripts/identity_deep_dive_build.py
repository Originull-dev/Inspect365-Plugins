"""Users and groups recipe (folder identity_deep_dive, id identity-deep-dive), v0.7.0. Facts only, built from saved
query results with no model.

    python3 skills/inspect365-report-recipes/recipes/identity_deep_dive/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

<run-dir>/run.json names the tenant and date; <run-dir>/inputs/<id>.json holds the response to each query in
queries.json, saved exactly as returned. Every value in the report is a fact in facts.json with the query it came
from. The text is labels, definitions and values: no summaries, judgments, advice or inferred labels such as
"service account" or "emergency access" (2026-10-05). It opens like every deep dive, with findings and then
Microsoft Secure Score (2026-10-06), and covers accounts, directory roles, high-impact users, sign-in methods,
licenses, guests and groups. Privileged roles follow Microsoft's isPrivileged flag, and roles eligible through PIM sit
beside active ones.

v0.5 follows the 2026-10-07 review: the working set leads the title band; a missing sign-in reads Never signed in;
licenses by Microsoft's product names replace the profile-field counts; sign-in methods open with every method the
enabled members registered; every finding check has a data view that shows its zeros; users the collected data marks
high impact carry the reason wherever they are listed; and Conditional Access is a part of this report, ported from the
conditional_access_deep_dive recipe (0.1.0, retired the same day): policies by state, the six-column policy table,
grant controls and authentication strengths, exclusions and device filters. Every query
reads one collection run, as on a prospect's first pull. No vendor name or branding: the report goes out under the
brand of whoever hands it over. The same inputs always produce the same bytes.

v0.6 (2026-10-07, second pass): licenses by product with the units purchased, assigned and available, and how many
sit on disabled accounts or on members with no sign-in in 45 days, to show over-licensing; the mailbox type bars are gone,
since the Mailboxes, Teams and SharePoint report shows the same accounts by mailbox type; the MFA registration and MFA risk
section is gone, since the product dropped the MFA risk check and authRisk needs Conditional Access context to mean
anything, and the enabled members not registered for MFA are listed under sign-in methods instead.

v0.6.1 (2026-10-08, after the dev MCP update): the MFA exclusion table lists only the policies the MCP counts for the
member's MFA coverage, ready for I365-574, which narrows that count to policies protecting sign-ins to cloud apps.

v0.7.0 (2026-10-14): guest invitations still pending acceptance, counted by how long
ago the guest was invited, as counts rather than a list; and the Teams resource accounts among the disabled accounts with
licenses, which Microsoft keeps disabled for sign-in and requires to hold the Teams Phone Resource Account license.
"""
import pathlib, re, sys
from collections import Counter, defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import IMPACT_REASON, SKU_NAME, Report, esc, n, sku, width  # noqa: E402

R = Report(__file__, 'identity-deep-dive', '0.7.0', 'Users and groups report')
D, fact, when = R.D, R.fact, R.when
NEVER = 'Never signed in'  # the label for an empty sign-in date (2026-10-07)


def signin(d):
    return R.day(d, none=NEVER)


# ---------------------------------------------------------------- knowledge tables (Microsoft's own labels and names)
# Table order only, most powerful first. Whether a role is privileged comes from the data: Microsoft's isPrivileged
# flag on each role, as collected on directoryRoles[] and eligiblePimRoles[].
ROLE_ORDER = ['Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
              'Security Administrator', 'Conditional Access Administrator', 'Application Administrator',
              'Cloud Application Administrator', 'Hybrid Identity Administrator', 'Authentication Administrator',
              'User Administrator', 'Intune Administrator', 'Helpdesk Administrator', 'Password Administrator',
              'Cloud Device Administrator', 'Domain Name Administrator', 'Security Operator', 'Global Reader',
              'Security Reader']
rank = lambda role: ROLE_ORDER.index(role) if role in ROLE_ORDER else len(ROLE_ORDER)
# Microsoft's system-preferred ranking groups these as phishing-resistant.
PHISHING_RESISTANT = {'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello',
                      'passKeySynced', 'fido2SecurityKey', 'windowsHelloForBusiness', 'platformCredential',
                      'macOsSecureEnclaveKey', 'x509CertificateMultiFactor'}
# Microsoft's description of each methodsRegistered value (Graph usageAuthMethod, Learn 2026-10-07), in tie-break order.
METHOD_NAME = {'passKeyDeviceBound': 'Device-bound passkey', 'passKeyDeviceBoundAuthenticator': 'Device-bound authenticator passkey',
               'passKeyDeviceBoundWindowsHello': 'Device-bound Windows Hello passkey', 'passKeySynced': 'Synced passkey',
               'fido2SecurityKey': 'FIDO2 security key', 'windowsHelloForBusiness': 'Windows Hello for Business',
               'macOsSecureEnclaveKey': 'macOS Secure Enclave key', 'platformCredential': 'Platform credential',
               'x509CertificateMultiFactor': 'Certificate-based authentication (multifactor)',
               'x509CertificateSingleFactor': 'Certificate-based authentication (single-factor)',
               'microsoftAuthenticatorPasswordless': 'Microsoft Authenticator passwordless',
               'microsoftAuthenticatorPush': 'Microsoft Authenticator push', 'softwareOneTimePasscode': 'Software one-time passcode',
               'hardwareOneTimePasscode': 'Hardware one-time passcode', 'oneTimePasscode': 'One-time passcode',
               'temporaryAccessPass': 'Temporary Access Pass', 'qrCode': 'QR code', 'externalAuthMethod': 'External authentication method',
               'mobilePhone': 'Mobile phone', 'alternateMobilePhone': 'Alternate mobile phone', 'officePhone': 'Office phone',
               'sms': 'SMS', 'email': 'Email', 'securityQuestion': 'Security question', 'appPassword': 'App password'}
METHOD_ORDER = list(METHOD_NAME)
# Microsoft's four group types (Learn, groups overview), keyed by the collected groupType.name, in table order.
# UnknownGroup is a combination of groupTypes, mailEnabled and securityEnabled that matches none of the four.
TYPE_NAME = {'Microsoft365Group': 'Microsoft 365 group', 'SecurityGroup': 'Security group',
             'MailEnabledSecurityGroup': 'Mail-enabled security group', 'DistributionGroup': 'Distribution group',
             'UnknownGroup': 'Unrecognized type'}
# Direct member bands: label, lowest, highest (None: no upper edge).
MEMBER_BANDS = [('None', 0, 0), ('1', 1, 1), ('2 to 10', 2, 10), ('11 to 50', 11, 50), ('51 to 250', 51, 250),
                ('More than 250', 251, None)]
ROW_CAP = 25  # group tables longer than this show the first 25 by a stated rule

# Conditional Access: Microsoft's labels (Entra admin center, Learn 2026-10-07)
STATE = {'enabled': 'On', 'enabledForReportingButNotEnforced': 'Report-only', 'disabled': 'Off'}
GUEST_TYPE = {'b2bCollaborationGuest': 'B2B collaboration guest users', 'b2bCollaborationMember': 'B2B collaboration member users',
              'b2bDirectConnectUser': 'B2B direct connect users', 'internalGuest': 'Local guest users',
              'serviceProvider': 'Service provider users', 'otherExternalUser': 'Other external users'}
TENANTS = {'all': 'All external Microsoft Entra organizations', 'enumerated': 'Selected external Microsoft Entra organizations'}
APP_SPECIAL = {'All': 'All resources', 'Office365': 'Office 365', 'MicrosoftAdminPortals': 'Microsoft Admin Portals', 'None': 'None'}
USER_ACTION = {'urn:user:registersecurityinfo': 'Register security information', 'urn:user:registerdevice': 'Register or join devices'}
CLIENT_APP = {'browser': 'Browser', 'mobileAppsAndDesktopClients': 'Mobile apps and desktop clients',
              'exchangeActiveSync': 'Exchange ActiveSync clients', 'easSupported': 'Exchange ActiveSync clients', 'other': 'Other clients'}
PLATFORM = {'all': 'Any device', 'android': 'Android', 'iOS': 'iOS', 'windowsPhone': 'Windows Phone', 'windows': 'Windows',
            'macOS': 'macOS', 'linux': 'Linux'}
RISK = {'high': 'High', 'medium': 'Medium', 'low': 'Low', 'none': 'No risk', 'hidden': 'Hidden'}
INSIDER = {'elevated': 'Elevated', 'moderate': 'Moderate', 'minor': 'Minor'}
FLOW = {'deviceCodeFlow': 'Device code flow', 'authenticationTransfer': 'Authentication transfer'}
LOCATION = {'All': 'Any network or location', 'AllTrusted': 'All trusted networks and locations'}
GRANT = {'block': 'Block access', 'mfa': 'Require multifactor authentication',
         'compliantDevice': 'Require device to be marked as compliant',
         'domainJoinedDevice': 'Require Microsoft Entra hybrid joined device', 'approvedApplication': 'Require approved client app',
         'compliantApplication': 'Require app protection policy', 'passwordChange': 'Require password change',
         'riskRemediation': 'Require risk remediation'}
STRENGTH = 'Require authentication strength'
OPERATOR = {'AND': 'Require all the selected controls', 'OR': 'Require one of the selected controls'}
STRENGTH_TYPE = {'builtIn': 'Built-in', 'custom': 'Custom'}
PERSIST = {'always': 'Always persistent', 'never': 'Never persistent'}
APP_CONTROL = {'monitorOnly': 'Monitor only', 'blockDownloads': 'Block downloads', 'mcasConfigured': 'Use custom policy'}
DF_MODE = {'exclude': ('Excludes devices where', 'Exclude filtered devices from policy'),
           'include': ('Only devices where', 'Include filtered devices in policy')}
DF_WORD = {'contains': 'contains', 'eq': 'is', 'in': 'is', 'ne': 'is not'}  # device filter words (2026-09-24)
GRANT_ROWS = ['Block access', 'Require multifactor authentication', STRENGTH, 'Require device to be marked as compliant',
              'Require Microsoft Entra hybrid joined device']  # always shown; other controls show when a policy uses them
NAME_CAP = 10  # policy name lists longer than this show the first ten by name and a count of the rest


# ---------------------------------------------------------------- helpers
def methods(r):
    return sorted(r.get('methodsRegistered') or [], key=lambda m: METHOD_ORDER.index(m) if m in METHOD_ORDER else 99)


def method_text(r):
    ms = methods(r)
    return ', '.join(D(METHOD_NAME.get(m, m)) for m in ms) if ms else 'None registered'


def has_pr(r):
    return any(m in PHISHING_RESISTANT for m in r.get('methodsRegistered') or [])


def roles_html(roles):
    return ', '.join(f'<b>{esc(D(x))}</b>' if x == 'Global Administrator' else esc(D(x)) for x in sorted(roles, key=lambda x: (rank(x), x)))


def flagged(names_, flags):
    """(role, isPrivileged) pairs from the parallel directoryRoles[] arrays. A role's flag is None when the value is
    missing, or for every role of the record when the two arrays differ in length; such roles never count as privileged."""
    names_, flags = list(names_ or []), list(flags or [])
    return list(zip(names_, flags if len(flags) == len(names_) else [None] * len(names_)))


def eligible(r):
    """(role, isPrivileged) pairs for roles eligible through PIM, or None when eligibility was not collected for the account."""
    e = r.get('eligiblePimRoles')
    return None if e is None else [(x.get('roleDisplayName') or x.get('roleTemplateId'), x.get('isPrivileged')) for x in e]


def privileged(pairs):
    return sorted({x for x, f in pairs or [] if f is True}, key=lambda x: (rank(x), x))


def names(pairs):
    return sorted({x for x, _ in pairs or []}, key=lambda x: (rank(x), x))



def sku_label(s):
    return D(SKU_NAME.get(sku(s), sku(s)))


def bars(counts, of, data=False):
    """Bar rows from a dict or (label, count) pairs; data=True records each label as a data string."""
    return [{'label': esc(D(k) if data else k), 'value': n(v), 'thin': True, 'pct': width(v, of), 'color': 'var(--series-1)'}
            for k, v in (counts.items() if isinstance(counts, dict) else counts)]


def first(rows, rule):
    """The note for a group table that shows only the first ROW_CAP rows."""
    return f' The first {n(ROW_CAP)} {rule}.' if len(rows) > ROW_CAP else ''


def raw_list(values):
    """Source values as a comma-separated list, each recorded as a data string."""
    return ', '.join(esc(D(v)) for v in values)


# ---------------------------------------------------------------- the working set
U_ALL = sorted(R.rows('users'), key=lambda u: (u['displayName'].lower(), u['id']))
kinds = Counter((u.get('userType'), u.get('accountEnabled') is True) for u in U_ALL)
accounts = fact('users.total', len(U_ALL), 'users')
members_n = fact('users.members', kinds[('Member', True)] + kinds[('Member', False)], 'users')
guests_n = fact('users.guests', kinds[('Guest', True)] + kinds[('Guest', False)], 'users')
enabled_n = fact('users.members_enabled', kinds[('Member', True)], 'users')
disabled_n = fact('users.members_disabled', kinds[('Member', False)], 'users')
guests_enabled = fact('users.guests_enabled', kinds[('Guest', True)], 'users')
disabled_all = fact('users.disabled', sum(1 for u in U_ALL if u.get('accountEnabled') is not True), 'users')

M = sorted(R.rows('members_enabled'), key=lambda r: (r['displayName'].lower(), r['id']))
if len(M) != enabled_n:
    sys.exit(f'members_enabled holds {len(M)} accounts and users counts {enabled_n} enabled members: run both queries again')
for r in M:
    r['_seen'], r['_try'], r['_created'] = when(r.get('lastSuccessfulSignInDateTime')), when(r.get('lastSignInDateTime')), when(r.get('createdDateTime'))
    r['_age'] = R.age(r['_seen'])
    D(r['displayName'])
    if r.get('jobTitle'):
        D(r['jobTitle'])

# ---------------------------------------------------------------- high impact (system.impactSources[] in the collected data)
HI = {u['id']: u for u in R.rows('high_impact_users')}
for u in HI.values():
    u['_types'] = sorted(set(u.get('system.impactSources[].type') or []), key=lambda t: list(IMPACT_REASON).index(t) if t in IMPACT_REASON else 99)
    u['_reason'] = '; '.join(D(IMPACT_REASON.get(t, t)) for t in u['_types'])
hi_n = fact('highImpact.users', len(HI), 'high_impact_users')
fact('highImpact.by_reason', dict(sorted(Counter(D(IMPACT_REASON.get(t, t)) for u in HI.values() for t in u['_types']).items())),
     'high_impact_users')


def impact(uid):
    """The High impact cell: the reasons in the collected data, or No."""
    return {'text': HI[uid]['_reason']} if uid in HI else {'text': 'No'}


# ---------------------------------------------------------------- sign-in and sign-in domain
REC = [('0 to 7 days', 0, 7), ('8 to 30 days', 8, 30), ('31 to 45 days', 31, 45), ('More than 45 days', 46, 10 ** 6)]
NEVER_OLD, NEVER_NEW = 'Never signed in, created more than 45 days ago', 'Never signed in, created in the last 45 days'
never = [r for r in M if r['_age'] is None]
never_old = [r for r in never if r['_created'] is None or R.age(r['_created']) > 45]
rec = fact('members.last_sign_in', {lab: sum(1 for r in M if r['_age'] is not None and lo <= r['_age'] <= hi) for lab, lo, hi in REC}
           | {NEVER_OLD: len(never_old), NEVER_NEW: len(never) - len(never_old)}, 'members_enabled')
over45 = fact('members.over_45_days', rec['More than 45 days'], 'members_enabled')
never_n = fact('members.never_signed_in', len(never), 'members_enabled')
fact('members.over_45_or_never', over45 + never_n, 'members_enabled')

no_lic = fact('members.no_license', sum(1 for r in M if not r.get('licenseDetails[].skuPartNumber')), 'members_enabled')
doms = sorted(Counter(r['userPrincipalName'].split('@')[-1].lower() for r in M).items(), key=lambda kv: (-kv[1], kv[0]))
fact('members.upn_domains', dict(doms), 'members_enabled')
dom_rows = doms[:5] + ([('Other domains', sum(c for _, c in doms[5:]))] if len(doms) > 5 else [])
if len(doms) > 5:
    fact('members.upn_domains_other', dom_rows[-1][1], 'members_enabled')

# ---------------------------------------------------------------- directory roles
# Active: assigned directly to the account (directoryRoles[]). Eligible: assigned through PIM to the account or to a group
# it is a direct member of (eligiblePimRoles[]). Privileged: Microsoft's isPrivileged flag on the role.
for r in M:
    r['_active'] = flagged(r.get('directoryRoles[].displayName'), r.get('directoryRoles[].isPrivileged'))
    r['_eligible'] = eligible(r)
    r['_act_priv'], r['_elig_priv'] = privileged(r['_active']), privileged(r['_eligible'])
ROLE_STATES = ['Privileged role, active', 'Privileged role, eligible through PIM only', 'Other directory roles only', 'No directory role']


def role_state(r):
    if r['_act_priv']:
        return ROLE_STATES[0]
    if r['_elig_priv']:
        return ROLE_STATES[1]
    return ROLE_STATES[2] if names(r['_active']) or names(r['_eligible']) else ROLE_STATES[3]


role_bars = fact('members.directory_roles', {s: sum(1 for r in M if role_state(r) == s) for s in ROLE_STATES}, 'members_enabled')
priv = sorted([r for r in M if r['_act_priv'] or r['_elig_priv']],
              key=lambda r: (0 if r['_act_priv'] else 1, rank((r['_act_priv'] or r['_elig_priv'])[0]), r['displayName'].lower(), r['id']))
priv_n = fact('privileged.enabled_members', len(priv), 'members_enabled')
priv_act_n = fact('privileged.active', sum(1 for r in priv if r['_act_priv']), 'members_enabled')
priv_elig_n = fact('privileged.eligible_only', priv_n - priv_act_n, 'members_enabled')
ga = fact('privileged.global_administrators', {
    'active': sum(1 for r in M if 'Global Administrator' in names(r['_active'])),
    'eligible': sum(1 for r in M if 'Global Administrator' in names(r['_eligible']))}, 'members_enabled')
fact('privileged.mfa_capable', sum(1 for r in priv if r.get('isMfaCapable') is True), 'members_enabled')
no_flag = fact('privileged.roles_without_flag', sum(1 for r in M for _, f in r['_active'] + (r['_eligible'] or []) if f is None), 'members_enabled')
pim_missing = fact('pim.not_collected', sum(1 for r in M if r['_eligible'] is None), 'members_enabled')
pim_none = pim_missing == len(M)  # eligibility not collected for the tenant
flag_only = [r for r in M if r.get('isAdmin') and not r['_active'] and not r['_eligible']]
fact('members.admin_flag_without_role', [r['displayName'] for r in flag_only], 'members_enabled')
priv_ids = {r['id'] for r in priv}
hi_outside = fact('highImpact.not_in_privileged_table', [HI[i]['displayName'] for i in sorted(HI, key=lambda i: HI[i]['displayName'].lower())
                                                         if i not in priv_ids], 'high_impact_users + members_enabled')

dis_roles = list({r['id']: r for q in ('disabled_with_eligible_roles', 'disabled_with_roles') for r in R.rows(q)}.values())
for r in dis_roles:
    r['_act'] = names(flagged(r.get('directoryRoles[].displayName'), None))
    r['_elig'] = None if eligible(r) is None else names(eligible(r))
dis_roles.sort(key=lambda r: (min([rank(x) for x in r['_act'] + (r['_elig'] or [])] or [len(ROLE_ORDER)]), r['displayName'].lower(), r['id']))
fact('disabled.with_roles', [r['displayName'] for r in dis_roles], 'disabled_with_roles + disabled_with_eligible_roles')
fact('disabled.with_global_admin', {'active': sum(1 for r in dis_roles if 'Global Administrator' in r['_act']),
                                    'eligible': sum(1 for r in dis_roles if 'Global Administrator' in (r['_elig'] or []))},
     'disabled_with_roles + disabled_with_eligible_roles')

# ---------------------------------------------------------------- sign-in methods and MFA registration
mcount = Counter(m for r in M for m in set(r.get('methodsRegistered') or []))
morder = sorted(mcount, key=lambda m: (-mcount[m], METHOD_ORDER.index(m) if m in METHOD_ORDER else 99, m))
fact('members.methods_registered', {m: mcount[m] for m in morder}, 'members_enabled')
no_method = fact('members.no_method_registered', sum(1 for r in M if not r.get('methodsRegistered')), 'members_enabled')
mfa_capable = fact('members.mfa_capable', sum(1 for r in M if r.get('isMfaCapable') is True), 'members_enabled')
pr_n = fact('members.phishing_resistant', sum(1 for r in M if has_pr(r)), 'members_enabled')
no_pr = [r for r in M if not has_pr(r)]
fact('members.without_phishing_resistant', [r['displayName'] for r in no_pr], 'members_enabled')
# Not MFA registered: Microsoft's isMfaRegistered is not true, the data view for Enabled User Without MFA and Admin Users
# Without MFA.
no_mfa = [r for r in M if r.get('isMfaRegistered') is not True]
fact('members.not_mfa_registered', [r['displayName'] for r in no_mfa], 'members_enabled')

# ---------------------------------------------------------------- guests
GU = R.rows('guests')
for g in GU:
    g['_age'], g['_created'] = R.age(when(g.get('lastSuccessfulSignInDateTime'))), when(g.get('createdDateTime'))
    em, upn = (g.get('mail') or '').lower(), g['userPrincipalName'].lower()
    g['_domain'] = em.split('@')[-1] if '@' in em else (upn.split('#ext#')[0].rsplit('_', 1)[-1] if '#ext#' in upn else upn.split('@')[-1])
gb = fact('guests.last_sign_in', {
    'Successful sign-in in the last 45 days': sum(1 for g in GU if g['_age'] is not None and g['_age'] <= 45),
    'Last successful sign-in more than 45 days ago': sum(1 for g in GU if g['_age'] is not None and g['_age'] > 45),
    'Never signed in, invited more than 45 days ago': sum(1 for g in GU if g['_age'] is None and (g['_created'] is None or R.age(g['_created']) > 45)),
    'Never signed in, invited in the last 45 days': sum(1 for g in GU if g['_age'] is None and g['_created'] is not None and R.age(g['_created']) <= 45)},
    'guests')
oldest = min((g['_created'] for g in GU if g['_age'] is None and g['_created']), default=None)
fact('guests.oldest_invitation_without_sign_in', R.day(oldest) if oldest else None, 'guests')
gdom = sorted(Counter(g['_domain'] for g in GU).items(), key=lambda kv: (-kv[1], kv[0]))
fact('guests.domains', dict(gdom), 'guests')
gdom_rows = gdom[:10] + ([('Other domains', sum(c for _, c in gdom[10:]))] if len(gdom) > 10 else [])
if len(gdom) > 10:
    fact('guests.domains_other', gdom_rows[-1][1], 'guests')
fact('guests.domain_count', len(gdom), 'guests')
# externalUserState (Graph user): PendingAcceptance or Accepted for a guest invited through the invitation API, null for other
# users. Invited: createdDateTime. Counts only (2026-10-14): how many invitations have waited more than 90 days.
INVITE = {'Accepted': 'Accepted', 'PendingAcceptance': 'Pending acceptance'}
unknown_state = sorted({g.get('externalUserState') for g in GU} - set(INVITE) - {None, ''})
if unknown_state:
    sys.exit(f'guests hold externalUserState values {unknown_state}: add labels to INVITE')
pend = [g for g in GU if g.get('externalUserState') == 'PendingAcceptance']
pend_age = [R.age(g['_created']) if g['_created'] else None for g in pend]
inv = fact('guests.invitations', {
    'Accepted': sum(1 for g in GU if g.get('externalUserState') == 'Accepted'),
    'Pending acceptance, invited in the last 30 days': sum(1 for a in pend_age if a is not None and a <= 30),
    'Pending acceptance, invited 31 to 90 days ago': sum(1 for a in pend_age if a is not None and 30 < a <= 90),
    'Pending acceptance, invited more than 90 days ago': sum(1 for a in pend_age if a is not None and a > 90),
    'Pending acceptance, no invitation date': sum(1 for a in pend_age if a is None),
    'No invitation state': sum(1 for g in GU if not g.get('externalUserState'))}, 'guests')
inv = {k: v for k, v in inv.items() if v or k != 'Pending acceptance, no invitation date'}
oldest_pending = min((g['_created'] for g in pend if g['_created']), default=None)
fact('guests.oldest_pending_invitation', R.day(oldest_pending) if oldest_pending else None, 'guests')
fact('guests.pending', len(pend), 'guests')

# ---------------------------------------------------------------- licenses on disabled accounts
dis_lic = sorted(R.rows('disabled_with_licenses'), key=lambda r: (r['displayName'].lower(), r['id']))
fact('disabled.with_licenses', [r['displayName'] for r in dis_lic], 'disabled_with_licenses')
# Teams resource accounts (Learn, "Microsoft Teams Phone Resource Account licenses" and "Manage resource accounts"): every
# resource account for an auto attendant or call queue needs the Teams Phone Resource Account license, that license is for
# resource accounts only, and those accounts stay disabled for sign-in (2026-10-14).
RESOURCE_SKU = 'PHONESYSTEM_VIRTUALUSER'
resource = {r['id'] for r in dis_lic if RESOURCE_SKU in (r.get('licenseDetails[].skuPartNumber') or [])}
fact('disabled.teams_resource_accounts', [r['displayName'] for r in dis_lic if r['id'] in resource], 'disabled_with_licenses')

# ---------------------------------------------------------------- licenses by product: purchased, assigned, available
# subscribedSkus (Learn, "View Microsoft 365 licenses and services with PowerShell"): prepaidUnits.enabled is the number of
# licenses purchased and consumedUnits the number assigned. prepaidUnits.warning holds units of an expired subscription in
# its grace period, which can still be assigned; suspended and locked-out units can't, so they are left out
# (2026-10-07: show what is available, to find over-licensing).
LARGE = fact('rules.largeUnitProducts', 10000, 'recipe rule: products with this many purchased units or more are listed last')
SUB_STATUS = {'Warning': 'In grace period', 'Suspended': 'Suspended', 'LockedOut': 'Locked out', 'Deleted': 'Deleted'}
org = R.rows('subscribed_skus')
if len(org) != 1:
    sys.exit(f'subscribed_skus returned {len(org)} organization records, expected 1')
SKU_FIELDS = ['skuId', 'skuPartNumber', 'capabilityStatus', 'consumedUnits', 'prepaidUnits.enabled', 'prepaidUnits.warning']
sku_cols = [org[0].get(f'subscribedSkus[].{k}') or [] for k in SKU_FIELDS]
if len({len(c) for c in sku_cols}) != 1:
    sys.exit('subscribed_skus returned SKU lists of different lengths, so they cannot be paired: run the query again')
units = lambda v: int(v or 0)
SKUS = [{'part': sku(r[1]), 'status': r[2], 'assigned': units(r[3]), 'purchased': units(r[4]), 'grace': units(r[5])}
        for r in zip(*sku_cols)]
if len({x['part'] for x in SKUS}) != len(SKUS):
    sys.exit('subscribed_skus lists a part number twice: the per-account counts join on it')
for x in SKUS:
    if x['status'] not in SUB_STATUS and x['status'] != 'Enabled':
        sys.exit(f'subscribed_skus holds capabilityStatus {x["status"]!r}: add a label to SUB_STATUS')
quiet45 = {r['id'] for r in M if (r['_age'] is not None and r['_age'] > 45)} | {r['id'] for r in never_old}
on_quiet = Counter(sku(s) for r in M if r['id'] in quiet45 for s in set(r.get('licenseDetails[].skuPartNumber') or []))
on_disabled = Counter(sku(s) for r in dis_lic for s in set(r.get('licenseDetails[].skuPartNumber') or []))
on_resource = fact('licenses.on_teams_resource_accounts', sum(len(set(r.get('licenseDetails[].skuPartNumber') or [])) for r in dis_lic
                                                             if r['id'] in resource), 'disabled_with_licenses')
lic_rows = [x for x in SKUS if x['purchased'] + x['grace'] + x['assigned'] > 0]
for x in lic_rows:
    x['available'] = x['purchased'] + x['grace'] - x['assigned']
    x['disabled'], x['quiet'] = on_disabled[x['part']], on_quiet[x['part']]
lic_rows.sort(key=lambda x: (x['purchased'] >= LARGE, 0 if x['purchased'] >= LARGE else -x['available'], sku_label(x['part']).casefold(), x['part']))
fact('licenses.products', {x['part']: {k: x[k] for k in ('purchased', 'grace', 'assigned', 'available', 'disabled', 'quiet', 'status')}
                           for x in lic_rows}, 'subscribed_skus + members_enabled + disabled_with_licenses')
lic_unlisted = fact('licenses.unlisted', len(SKUS) - len(lic_rows), 'subscribed_skus')
fact('licenses.listed', len(lic_rows), 'subscribed_skus')
lic_grace = any(x['grace'] for x in lic_rows)

# ---------------------------------------------------------------- groups
GR = sorted(R.rows('groups'), key=lambda g: (g['displayName'].lower(), g['id']))
for g in GR:
    D(g['displayName'])
    g['_type'] = g.get('groupType.name') if g.get('groupType.name') in TYPE_NAME else 'UnknownGroup'
    g['_dynamic'] = g.get('groupType.isDynamic') is True
    g['_rag'] = g.get('isAssignableToRole') is True
    g['_members'], g['_owners'], g['_guests'] = (int(g.get(f'summary.{k}') or 0) for k in ('membersCount', 'ownersCount', 'guestsCount'))
groups_n = fact('groups.total', len(GR), 'groups')
gtypes = [k for k in TYPE_NAME if k != 'UnknownGroup' or any(g['_type'] == k for g in GR)]
by_type = fact('groups.by_type', {TYPE_NAME[k]: {'groups': sum(g['_type'] == k for g in GR),
                                                 'assigned': sum(g['_type'] == k and not g['_dynamic'] for g in GR),
                                                 'dynamic': sum(g['_type'] == k and g['_dynamic'] for g in GR),
                                                 'roleAssignable': sum(g['_type'] == k and g['_rag'] for g in GR)} for k in gtypes}, 'groups')
dyn_n = fact('groups.dynamic', sum(g['_dynamic'] for g in GR), 'groups')
assigned_n = fact('groups.assigned', groups_n - dyn_n, 'groups')

rag = []
for g in GR:
    if g['_rag']:
        pairs = flagged(g.get('directoryRoles[].displayName'), g.get('directoryRoles[].isPrivileged'))
        rag.append({'id': g['id'], 'name': g['displayName'], 'members': g['_members'], 'guests': g['_guests'],
                    'roles': [x for x, _ in pairs], 'priv': len(privileged(pairs)), 'noflag': sum(1 for _, f in pairs if f is None)})
rag.sort(key=lambda g: (-g['priv'], g['members'], g['name'].lower(), g['id']))
rag_n = fact('groups.role_assignable_count', len(rag), 'groups')
fact('groups.role_assignable', [{'name': g['name'], 'members': g['members'], 'guests': g['guests'], 'roles': len(g['roles']),
                                 'privileged_roles': g['priv']} for g in rag], 'groups')
rag_guests = fact('groups.role_assignable_with_guests', sum(1 for g in rag if g['guests'] > 0), 'groups')
rag_no_flag = fact('groups.roles_without_flag', sum(g['noflag'] for g in rag), 'groups')

m365 = [g for g in GR if g['_type'] == 'Microsoft365Group']
m365_n = fact('groups.m365_total', len(m365), 'groups')
own = fact('groups.m365_owners', {'No owner': sum(g['_owners'] == 0 for g in m365), 'One owner': sum(g['_owners'] == 1 for g in m365),
                                  'Two or more owners': sum(g['_owners'] >= 2 for g in m365)}, 'groups')
ownerless = [g for g in m365 if g['_owners'] == 0]
fact('groups.m365_without_owner', [{'name': g['displayName'], 'members': g['_members'], 'created': R.day(when(g.get('createdDateTime')))}
                                   for g in ownerless], 'groups')
expiring = sorted([g for g in m365 if g.get('expirationDateTime')], key=lambda g: (when(g['expirationDateTime']), g['displayName'].lower(), g['id']))
for g in expiring:
    g['_days'] = (when(g['expirationDateTime']) - R.AS_OF).days
EXP_PAST, EXP_SOON, EXP_LATER, EXP_NONE = ('Past its expiration date', 'Expires in the next 30 days', 'Expires in more than 30 days',
                                           'No expiration date')
exp = fact('groups.m365_expiration', {EXP_PAST: sum(1 for g in expiring if g['_days'] < 0),
                                      EXP_SOON: sum(1 for g in expiring if 0 <= g['_days'] <= 30),
                                      EXP_LATER: sum(1 for g in expiring if g['_days'] > 30),
                                      EXP_NONE: m365_n - len(expiring)}, 'groups')
if expiring:
    fact('groups.m365_expiration_soonest', [{'name': g['displayName'], 'expires': R.day(when(g['expirationDateTime'])), 'owners': g['_owners']}
                                            for g in expiring[:ROW_CAP]], 'groups')

fact('groups.direct_member_bands', {lab: [lo, hi] for lab, lo, hi in MEMBER_BANDS}, 'recipe definition')
bands = fact('groups.by_direct_members', {lab: sum(g['_members'] >= lo and (hi is None or g['_members'] <= hi) for g in GR)
                                          for lab, lo, hi in MEMBER_BANDS}, 'groups')
with_guests = sorted([g for g in GR if g['_guests'] > 0], key=lambda g: (-g['_guests'], g['displayName'].lower(), g['id']))
fact('groups.with_guest_members', [{'name': g['displayName'], 'type': TYPE_NAME[g['_type']], 'guests': g['_guests'],
                                    'members': g['_members'], 'owners': g['_owners']} for g in with_guests], 'groups')
if max(len(ownerless), len(with_guests), len(expiring)) > ROW_CAP:
    fact('groups.table_row_cap', ROW_CAP, 'recipe definition')

# ---------------------------------------------------------------- Conditional Access: lookups by id
U = {u['id']: u for u in U_ALL}
G = {g['id']: g for g in GR}
ROLE = {r['roleTemplateId']: r['displayName'] for r in sorted(R.rows('directory_roles'), key=lambda r: r['id']) if r.get('roleTemplateId')}
APP, SP = {}, {}
for s in sorted(R.rows('service_principals'), key=lambda s: s['id']):
    APP.setdefault(s.get('appId'), s.get('displayName'))
    SP[s['id']] = s.get('displayName')
UNRESOLVED = defaultdict(set)


def key(s):
    return (str(s).casefold(), str(s))


def resolved(kind, ident, name):
    if name:
        return D(name)
    UNRESOLVED[kind].add(ident)
    return f'{D(ident)} (name not in collected data)'


def user_name(uid):
    u = U.get(uid)
    if not u:
        return resolved('users', uid, None)
    return D(u['displayName']) + (' (disabled)' if u.get('accountEnabled') is False else '')


def group_name(gid):
    return resolved('groups', gid, (G.get(gid) or {}).get('displayName'))


def role_name(tid):
    return resolved('directory roles', tid, ROLE.get(tid))


def app_name(aid):
    return APP_SPECIAL.get(aid) or resolved('applications', aid, APP.get(aid))


def sp_name(sid):
    return 'All owned service principals' if sid == 'ServicePrincipalsInMyTenant' else resolved('service principals', sid, SP.get(sid))


def plural(k, label):
    return label if k == 1 else {'directory role': 'directory roles', 'guest or external user type': 'guest or external user types',
                                 'workload identity': 'workload identities'}.get(label, label + 's')


# ---------------------------------------------------------------- Conditional Access: policies
P = sorted(R.rows('policies'), key=lambda p: (*key(p['displayName']), p['id']))
for p in P:
    D(p['displayName'])
by_state = {STATE[s]: sum(p['state'] == s for p in P) for s in STATE}
total = fact('ca.policies.total', len(P), 'policies')
fact('ca.policies.by_state', by_state, 'policies')
on_n, ro_n, off_n = by_state['On'], by_state['Report-only'], by_state['Off']
L = [p for p in P if p['state'] != 'disabled']  # listed: on and report-only
listed = fact('ca.policies.listed', len(L), 'policies')
RO = {p['id'] for p in L if p['state'] == 'enabledForReportingButNotEnforced'}


def pname(p, mark=True):
    return D(p['displayName']) + (' (report-only)' if mark and p['id'] in RO else '')


def assignments(p, side):
    """Users, groups, roles, guest types and workload identities a policy includes or excludes, as sorted display names."""
    raw = p.get(f'conditions.users.{side}Users[]') or []
    types = [t for t in (p.get(f'conditions.users.{side}GuestsOrExternalUsers.guestOrExternalUserTypes') or '').split(',') if t and t != 'none']
    guests = [D(GUEST_TYPE.get(t, t)) for t in sorted(types, key=lambda t: list(GUEST_TYPE).index(t) if t in GUEST_TYPE else 99)]
    if 'GuestsOrExternalUsers' in raw:
        guests.insert(0, 'All guest and external users')
    return {'user': sorted((user_name(x) for x in raw if x not in ('All', 'None', 'GuestsOrExternalUsers')), key=key),
            'group': sorted((group_name(x) for x in p.get(f'conditions.users.{side}Groups[]') or []), key=key),
            'directory role': sorted((role_name(x) for x in p.get(f'conditions.users.{side}Roles[]') or []), key=key),
            'guest or external user type': guests,
            'workload identity': sorted((sp_name(x) for x in p.get(f'conditions.clientApplications.{side}ServicePrincipals[]') or []), key=key)}


def counted(kinds_, exclude=False):
    """One kind with one or two entries is named; anything longer or mixed is counted (2026-09-24)."""
    present = [(k, v) for k, v in kinds_.items() if v]
    if not present:
        return None
    if len(present) == 1 and len(present[0][1]) <= 2:
        k, v = present[0]
        label = plural(len(v), k)
        return (f'Exclude {label}: ' if exclude else f'{label[0].upper()}{label[1:]}: ') + ', '.join(esc(x) for x in v)
    return ('Exclude: ' if exclude else '') + ', '.join(f'{n(len(v))} {plural(len(v), k)}' for k, v in present)


def users_cell(p):
    inc = p.get('conditions.users.includeUsers[]') or []
    a_in, a_ex = assignments(p, 'include'), assignments(p, 'exclude')
    head = 'All users' if 'All' in inc else (counted(a_in) or 'None')
    lines = [head] + ([counted(a_ex, exclude=True)] if counted(a_ex) else [])
    return lines, {'include': {k: len(v) for k, v in a_in.items() if v}, 'exclude': {k: len(v) for k, v in a_ex.items() if v}}


def named_or_counted(items, noun, exclude=False):
    text = ', '.join(esc(x) for x in items) if len(items) <= 2 else f'{n(len(items))} {noun}s'
    return ('Exclude: ' if exclude else '') + text


def resources_cell(p):
    inc = [app_name(a) for a in p.get('conditions.applications.includeApplications[]') or []]
    exc = sorted((app_name(a) for a in p.get('conditions.applications.excludeApplications[]') or []), key=key)
    lines = [named_or_counted(sorted(inc, key=key) if len(inc) > 1 else inc, 'resource')] if inc else []
    lines += ['User action: ' + esc(D(USER_ACTION.get(a, a))) for a in p.get('conditions.applications.includeUserActions[]') or []]
    lines += ['Authentication context: ' + esc(D(c)) for c in p.get('conditions.applications.includeAuthenticationContextClassReferences[]') or []]
    if p.get('conditions.applications.applicationFilter.rule'):
        lines.append(('Exclude' if p.get('conditions.applications.applicationFilter.mode') == 'exclude' else 'Include')
                     + ' filtered resources: ' + esc(D(p['conditions.applications.applicationFilter.rule'])))
    lines = lines or ['None']
    if exc:
        lines.append(named_or_counted(exc, 'resource', exclude=True))
    return lines, {'resources': len(inc), 'excludedResources': len(exc)}


def device_filter_words(mode, rule):
    """The rule in words: -contains reads contains, -eq and -in read is, -ne reads is not, and consecutive clauses on the same
    property and operator join into one list. None when the rule mixes -and with -or, uses parentheses or another operator."""
    if '(' in rule or ')' in rule:
        return None
    parts = re.split(r'\s+-(or|and)\s+', rule.strip(), flags=re.I)
    joins = {j.lower() for j in parts[1::2]}
    if len(joins) > 1:
        return None
    join = joins.pop() if joins else 'or'
    groups = []
    for clause in parts[0::2]:
        m = re.fullmatch(r'device\.(\w+)\s+-(\w+)\s+(\[[^\]]*\]|"[^"]*"|\S+)', clause.strip(), flags=re.I)
        if not m or m.group(2).lower() not in DF_WORD:
            return None
        prop, op, raw = m.group(1), m.group(2).lower(), m.group(3)
        if op == 'in':
            if not raw.startswith('['):
                return None
            values = [v.strip().strip('"') for v in raw[1:-1].split(',') if v.strip()]
        else:
            values = [raw.strip('"')]
        for v in values:
            D(v)
        if join == 'or' and groups and groups[-1][:2] == (prop, op):
            groups[-1][2].extend(values)
        else:
            groups.append((prop, op, values))

    def listed_values(vs):
        return vs[0] if len(vs) == 1 else ', '.join(vs[:-1]) + f' or {vs[-1]}'
    text = f', {join} '.join(f'{D(prop)} {DF_WORD[op]} {listed_values(vs)}' for prop, op, vs in groups)
    return f'{DF_MODE[mode][0]} {text}'


def location_text(ids):
    labels = [LOCATION[x] for x in ids if x in LOCATION]
    named = [x for x in ids if x not in LOCATION]
    if named:
        labels.append(f'{n(len(named))} named location{"" if len(named) == 1 else "s"}')
    return ', '.join(labels), len(named)


def conditions(p):
    """(condition, setting) for each condition the policy sets, for the policy table's Conditions column."""
    out, named = [], {}
    apps = p.get('conditions.clientAppTypes') or []
    if apps and apps != ['all']:
        out.append(('Client apps', ', '.join(dict.fromkeys(D(CLIENT_APP.get(a, a)) for a in apps))))
    inc, exc = p.get('conditions.platforms.includePlatforms[]'), p.get('conditions.platforms.excludePlatforms[]') or []
    if inc:
        out.append(('Device platforms', ', '.join(D(PLATFORM.get(x, x)) for x in inc)
                    + ('; exclude ' + ', '.join(D(PLATFORM.get(x, x)) for x in exc) if exc else '')))
    if p.get('conditions.locations.includeLocations[]') is not None:
        inc_t, inc_n = location_text(p['conditions.locations.includeLocations[]'])
        exc_t, exc_n = location_text(p.get('conditions.locations.excludeLocations[]') or [])
        named = {'include': inc_n, 'exclude': exc_n}
        out.append(('Network', (inc_t or 'None') + (f'; exclude {exc_t}' if exc_t else '')))
    for field, label, labels in (('signInRiskLevels', 'Sign-in risk', RISK), ('userRiskLevels', 'User risk', RISK),
                                 ('servicePrincipalRiskLevels', 'Service principal risk', RISK), ('insiderRiskLevels', 'Insider risk', INSIDER)):
        levels = p.get(f'conditions.{field}') or []
        levels = [levels] if isinstance(levels, str) else levels
        if levels:
            out.append((label, ', '.join(D(labels.get(x, x)) for x in sorted(levels, key=lambda x: list(labels).index(x) if x in labels else 99))))
    rule = p.get('conditions.devices.deviceFilter.rule')
    if rule:
        mode = p.get('conditions.devices.deviceFilter.mode') or 'exclude'
        out.append(('Device filter', device_filter_words(mode, D(rule)) or f'{DF_MODE[mode][0]}: {rule}'))
    flows = [f for f in (p.get('conditions.authenticationFlows.transferMethods') or '').split(',') if f and f != 'none']
    if flows:
        out.append(('Authentication flows', ', '.join(D(FLOW.get(f, f)) for f in flows)))
    return out, named


def grant_controls(p):
    order = list(GRANT)
    ctl = [GRANT.get(c, c) for c in sorted(p.get('grantControls.builtInControls') or [], key=lambda c: order.index(c) if c in order else 99)]
    if p.get('grantControls.authenticationStrength.id'):
        ctl.append(STRENGTH)
    if p.get('grantControls.termsOfUse') or []:
        ctl.append('Terms of use')
    ctl += ['Custom control' for _ in p.get('grantControls.customAuthenticationFactors') or []]
    return ctl


def grant_cell(p):
    lines = []
    for c in grant_controls(p):
        if c == STRENGTH:
            lines.append(f'{STRENGTH}: ' + esc(D(p.get('grantControls.authenticationStrength.displayName') or p['grantControls.authenticationStrength.id'])))
        elif c == 'Terms of use':
            k = len(p.get('grantControls.termsOfUse'))
            lines.append(f'Terms of use: {n(k)} agreement{"" if k == 1 else "s"}')
        elif c != 'Custom control':
            lines.append(esc(D(c)))
    lines += ['Custom control: ' + esc(D(c)) for c in p.get('grantControls.customAuthenticationFactors') or []]
    if len(grant_controls(p)) > 1:
        lines.append(esc(D(OPERATOR.get(p.get('grantControls.operator'), p.get('grantControls.operator') or ''))))
    return lines or ['None']


def session_cell(p):
    lines, sif = [], None
    if p.get('sessionControls.signInFrequency.isEnabled'):
        if p.get('sessionControls.signInFrequency.frequencyInterval') == 'everyTime':
            lines.append('Sign-in frequency: Every time')
            sif = 'Every time'
        else:
            unit, value = p.get('sessionControls.signInFrequency.type') or '', p.get('sessionControls.signInFrequency.value')
            if value is None:
                lines.append(f'Sign-in frequency: {esc(D(unit))}, value not collected')
                sif = 'value not collected'
            else:
                sif = value
                lines.append(f'Sign-in frequency: {n(value)} {unit[:-1] if value == 1 and unit.endswith("s") else unit}')
    if p.get('sessionControls.persistentBrowser.isEnabled'):
        lines.append('Persistent browser session: ' + esc(D(PERSIST.get(p.get('sessionControls.persistentBrowser.mode'), p.get('sessionControls.persistentBrowser.mode') or ''))))
    if p.get('sessionControls.cloudAppSecurity.isEnabled'):
        t = p.get('sessionControls.cloudAppSecurity.cloudAppSecurityType')
        lines.append('Use Conditional Access App Control: ' + esc(D(APP_CONTROL.get(t, t or ''))))
    if p.get('sessionControls.disableResilienceDefaults'):
        lines.append('Disable resilience defaults')
    return lines or ['None'], sif


TABLE, CELLS, DF_ROWS = [], {}, []
for p in L:
    u_lines, u_counts = users_cell(p)
    r_lines, r_counts = resources_cell(p)
    conds, named = conditions(p)
    s_lines, sif = session_cell(p)
    CELLS[p['displayName']] = {**u_counts, **r_counts, 'namedLocations': named, 'signInFrequency': sif}
    TABLE.append({'policy': {'text': p['displayName'], 'sub': f"Modified {str(p.get('modifiedDateTime') or '')[:10] or 'not on record'}",
                             **({'status': 'Report-only'} if p['id'] in RO else {})},
                  'users': {'html': '<br>'.join(u_lines)}, 'res': {'html': '<br>'.join(r_lines)},
                  'cond': {'html': '<br>'.join(f'{esc(c)}: {esc(s)}' for c, s in conds) or 'None'},
                  'grant': {'html': '<br>'.join(grant_cell(p))}, 'session': {'html': '<br>'.join(s_lines)}})
    if p.get('conditions.devices.deviceFilter.rule'):
        mode = p.get('conditions.devices.deviceFilter.mode') or 'exclude'
        DF_ROWS.append((p, DF_MODE[mode][1], device_filter_words(mode, p['conditions.devices.deviceFilter.rule']),
                        p['conditions.devices.deviceFilter.rule']))
fact('ca.policies.table', CELLS, 'policies + users + groups + directory_roles + service_principals')
fact('ca.device_filters', [p['displayName'] for p, *_ in DF_ROWS], 'policies')

# ---------------------------------------------------------------- Conditional Access: grant controls
CAPPED = {}


def names_html(policies, what):
    """Policy names, report-only marked, the first NAME_CAP by name when longer."""
    names_ = sorted((pname(p) for p in policies), key=key)
    if len(names_) > NAME_CAP:
        CAPPED[what] = len(names_) - NAME_CAP
        names_ = names_[:NAME_CAP] + [f'and {n(len(names_) - NAME_CAP)} more']
    return '<br>'.join(esc(x) for x in names_) if names_ else 'None'


def capped(panel, before):
    """Adds the cut-list sentence to a panel whose name lists were cut while it was built."""
    if len(CAPPED) > before:
        panel['note'] = f"{panel.get('note', '')} Lists longer than {n(NAME_CAP)} names show the first {n(NAME_CAP)} by name.".strip()
    return panel


grant_use = defaultdict(list)
for p in L:
    for c in grant_controls(p) or ['No grant control']:
        grant_use[c].append(p)
rows_order = GRANT_ROWS + [c for c in list(GRANT.values()) + ['Terms of use', 'Custom control'] if c not in GRANT_ROWS and grant_use.get(c)]
if grant_use.get('No grant control'):
    rows_order.append('No grant control')
grants = fact('ca.grant.controls', {c: {'on': sum(p['id'] not in RO for p in grant_use[c]), 'reportOnly': sum(p['id'] in RO for p in grant_use[c])}
                                    for c in rows_order}, 'policies')
requires_mfa = lambda p: 'Require multifactor authentication' in grant_controls(p) or STRENGTH in grant_controls(p)
mfa_on = [p for p in L if p['id'] not in RO and requires_mfa(p)]
mfa_ro = [p for p in L if p['id'] in RO and requires_mfa(p)]
kpi_mfa = fact('ca.policies.on_requiring_mfa_or_strength', {
    'total': len(mfa_on),
    'Require multifactor authentication': sum('Require multifactor authentication' in grant_controls(p) for p in mfa_on),
    STRENGTH: sum(STRENGTH in grant_controls(p) for p in mfa_on)}, 'policies')
fact('ca.policies.report_only_requiring_mfa_or_strength', len(mfa_ro), 'policies')

strengths = {}
for p in L:
    sid = p.get('grantControls.authenticationStrength.id')
    if sid:
        s = strengths.setdefault(sid, {'name': D(p.get('grantControls.authenticationStrength.displayName') or sid),
                                       'type': D(STRENGTH_TYPE.get(p.get('grantControls.authenticationStrength.policyType'),
                                                                   p.get('grantControls.authenticationStrength.policyType') or 'Not collected')),
                                       'satisfied': D(p.get('grantControls.authenticationStrength.requirementsSatisfied') or 'not collected'),
                                       'combos': [D(c) for c in p.get('grantControls.authenticationStrength.allowedCombinations') or []],
                                       'policies': []})
        s['policies'].append(p)
fact('ca.grant.authentication_strengths', {s['name']: {'type': s['type'], 'allowedCombinations': s['combos'],
                                                       'policies': sorted(pname(p) for p in s['policies'])}
                                           for s in strengths.values()}, 'policies')

# ---------------------------------------------------------------- Conditional Access: exclusions
EXCL = []
for p in L:
    a = assignments(p, 'exclude')
    a['resource'] = sorted((app_name(x) for x in p.get('conditions.applications.excludeApplications[]') or []), key=key)
    if any(a.values()):
        EXCL.append((p, a))
group_members = {}
for p, _ in EXCL:
    for gid in p.get('conditions.users.excludeGroups[]') or []:
        if gid in G:
            group_members[G[gid]['displayName']] = G[gid]['_members']
fact('ca.exclusions.by_policy', {p['displayName']: {k: len(v) for k, v in a.items() if v} for p, a in EXCL}, 'policies + users + groups + directory_roles')
fact('ca.exclusions.group_direct_members', dict(sorted(group_members.items())), 'groups')

POLICY = {p['id']: p for p in P}
VIA = {'excludedGroup': 'Group', 'excludedRole': 'Directory role', 'excludedGuestType': 'Guest or external user type'}
X = sorted(R.rows('members_excluded_from_mfa'), key=lambda u: (*key(u['displayName']), u['id']))
x_rows = []
for u in X:
    ids, reasons = u.get('caPolicies[].id') or [], u.get('caPolicies[].via.reason') or []
    vnames, via_ids = u.get('caPolicies[].via.displayName') or [], u.get('caPolicies[].via.id') or []
    if not (len(ids) == len(reasons) == len(vnames) == len(via_ids)):
        sys.exit(f'members_excluded_from_mfa: caPolicies[] arrays differ in length for {u["id"]}')
    vias = []
    # List only the policies the MCP counts for this member's MFA coverage. Since I365-574 it counts only policies that
    # protect sign-ins to cloud apps (appScope all or someApps), while caPolicies[] still lists step-up policies such as one
    # that targets only an authentication context. Today both lists match for every member.
    covered = set(u.get('mfaPolicyCoverage.policyIds') or [])
    for pid, reason, vname, vid in zip(ids, reasons, vnames, via_ids):
        if covered and pid not in covered:
            continue
        if reason == 'excludedDirectly':
            how = 'Listed directly'
        elif reason == 'excludedGroup':
            how = f'Group: {group_name(vid) if vid in G else D(vname or vid)}'
        elif reason == 'excludedGuestType':
            how = f'{VIA[reason]}: {D(GUEST_TYPE.get(vname, vname or ""))}'
        else:
            how = f'{VIA.get(reason, reason)}: {D(vname or vid or "")}'
        vias.append((pname(POLICY[pid], mark=False) if pid in POLICY else D(pid), how))
    vias.sort(key=lambda v: key(v[0]))
    D(u['displayName'])
    D(u.get('userPrincipalName') or '')
    x_rows.append((u, vias))
fact('ca.members.excluded_from_every_mfa_policy', {u['displayName']: [f'{a}: {b}' for a, b in v] for u, v in x_rows}, 'members_excluded_from_mfa')
excluded_n = fact('ca.members.excluded_from_every_mfa_policy_count', len(x_rows), 'members_excluded_from_mfa')
fact('ca.members.excluded_from_every_mfa_policy_high_impact', sum(1 for u, _ in x_rows if u['id'] in HI), 'members_excluded_from_mfa + high_impact_users')

# ================================================================ the report
# ---------------------------------------------------------------- opening: hero, figures, findings, Secure Score
R.hero(f'Findings, Microsoft Secure Score, accounts, directory roles, high-impact users, sign-in methods, licenses, guests, groups '
       f'and Conditional Access policies of the {R.tenant_raw} Microsoft 365 tenant, from data collected on {R.as_of}.',
       scope=[('Accounts', n(accounts), f'Members: {n(members_n)}'),
              ('Enabled members', n(enabled_n), f'Disabled members: {n(disabled_n)}'),
              ('Guests', n(guests_n), f'Enabled: {n(guests_enabled)}'),
              ('Groups', n(groups_n), f'Microsoft 365 groups: {n(m365_n)}')])
R.kpis([
    {'kicker': 'Enabled members MFA capable', 'value': n(mfa_capable), 'unit': f' of {n(enabled_n)}',
     'foot': f'Microsoft’s isMfaCapable. With a phishing-resistant method: {n(pr_n)}'},
    {'kicker': 'Enabled members with a privileged role', 'value': n(priv_n),
     'foot': f'Active roles only; PIM eligibility was not collected. Global Administrator: {n(ga["active"])}' if pim_none else
             f'Active: {n(priv_act_n)}. Eligible through PIM only: {n(priv_elig_n)}. '
             f'Global Administrator: {n(ga["active"])} active, {n(ga["eligible"])} eligible'},
    {'kicker': 'Enabled members, no successful sign-in in 45 days', 'value': n(over45 + never_n),
     'foot': f'Last success more than 45 days ago: {n(over45)}. Never signed in: {n(never_n)}'},
    {'kicker': 'Conditional Access policies on', 'value': n(on_n), 'unit': f' of {n(total)}',
     'foot': f'Requiring MFA or an authentication strength: {n(kpi_mfa["total"])}. Report-only: {n(ro_n)}. Off: {n(off_n)}'},
])
R.findings('user_group_findings_open', 'user_group_findings_accepted', ['Identity', 'Group'], 'User and group findings')
R.secure_score('secure_score', 'secure_score_controls', 'identity', 'Recommended actions in Microsoft’s Identity category')

# ---------------------------------------------------------------- enabled members: sign-in and sign-in domain
R.add({'type': 'panels', 'kicker': 'Enabled members', 'title': 'Last successful sign-in and sign-in domain', 'cols': 2, 'panels': [
    {'kicker': f'Last successful sign-in, {n(enabled_n)} enabled members', 'bars': bars(rec, enabled_n),
     'note': 'From lastSuccessfulSignInDateTime, which counts interactive and non-interactive sign-ins and is the field the '
             'dormancy findings use. Never signed in: the field is empty; Microsoft records it from December 1, 2023. Created: '
             'createdDateTime.'},
    {'kicker': 'Sign-in domain', 'bars': bars(dict(dom_rows), enabled_n, data=True)}]}, 'sign-in')

# ---------------------------------------------------------------- licenses: by product, then on disabled accounts


def product_cell(x):
    label, bits = sku_label(x['part']), []
    if label != x['part']:
        bits.append(D(x['part']))
    if x['status'] != 'Enabled':
        bits.append(f'Subscription: {SUB_STATUS[x["status"]]} (Graph: {D(x["status"])})')
    return {'text': label, 'sub': ' · '.join(bits)} if bits else {'text': label}


lic_cols = [{'key': 'product', 'label': 'Product'}, {'key': 'purchased', 'label': 'Purchased', 'n': True}]
lic_cols += [{'key': 'grace', 'label': 'In grace period', 'n': True}] if lic_grace else []
lic_cols += [{'key': 'assigned', 'label': 'Assigned', 'n': True}, {'key': 'available', 'label': 'Available', 'n': True},
             {'key': 'disabled', 'label': 'On disabled accounts', 'n': True},
             {'key': 'quiet', 'label': 'On members with no sign-in in 45 days', 'n': True}]
lic_note = ('Purchased: prepaidUnits.enabled, the licenses bought for the product. '
            + ('In grace period: prepaidUnits.warning, units of an expired subscription that can still be assigned until Microsoft '
               'suspends them. Available: purchased plus in grace period, less assigned. ' if lic_grace else
               'Available: purchased less assigned. ')
            + 'Assigned: consumedUnits. On disabled accounts: licenses of the product on accounts with accountEnabled false, any '
              'account type. On members with no sign-in in 45 days: licenses on enabled members whose last successful sign-in is '
              'more than 45 days before collection, or who never signed in and were created more than 45 days before it. Both are '
              f'part of Assigned. Products with {n(LARGE)} or more units purchased are listed last, by name; the rest by units '
              'available. '
            + (f'Not listed: {n(lic_unlisted)} products with no purchased, in-grace or assigned units. ' if lic_unlisted else '')
            + f'Enabled members with no license: {n(no_lic)}.'
            + (f' On disabled accounts includes {n(on_resource)} licenses on {n(len(resource))} Teams resource accounts, listed under '
               'Licenses on disabled accounts.' if resource else ''))
R.add({'type': 'panels', 'kicker': 'Licenses', 'title': 'Licenses: purchased, assigned and available', 'cols': 1, 'panels': [{
    'kicker': f'Products: {n(len(lic_rows))}', 'cols': lic_cols,
    'rows': [{'product': product_cell(x), 'purchased': n(x['purchased']), 'grace': n(x['grace']), 'assigned': n(x['assigned']),
              'available': n(x['available']), 'disabled': n(x['disabled']), 'quiet': n(x['quiet'])} for x in lic_rows],
    'note': lic_note} if lic_rows else {'kicker': 'Products: 0', 'note': 'The collected data holds no subscribed license products.'}]},
      'licenses')

dis_note = 'Disabled: accountEnabled is false, any account type.'
res_note = (' Teams resource account: the account holds the Microsoft Teams Phone Resource Account license. Microsoft’s documentation '
            'says that license is only for resource accounts of auto attendants and call queues, each of those accounts needs it, and '
            'they stay disabled for sign-in.') if resource else ''
lic_kicker = (f'Disabled accounts with licenses: {n(len(dis_lic))} of {n(disabled_all)}'
              + (f'. Teams resource accounts: {n(len(resource))}' if resource else ''))
R.add({'type': 'panels', 'kicker': 'Licenses', 'title': 'Licenses on disabled accounts', 'cols': 1, 'panels': [{
    'kicker': lic_kicker,
    'cols': [{'key': 'account', 'label': 'Disabled account'}, {'key': 'hi', 'label': 'High impact'}, {'key': 'lic', 'label': 'Licenses'},
             {'key': 'last', 'label': 'Last successful sign-in'}],
    'rows': [{'account': {'mono': D(r['displayName']), **({'sub': 'Teams resource account'} if r['id'] in resource else {})}, 'hi': impact(r['id']),
              'lic': esc(', '.join(sku_label(s) for s in sorted(r['licenseDetails[].skuPartNumber'], key=lambda s: (sku_label(s).casefold(), s)))),
              'last': signin(when(r.get('lastSuccessfulSignInDateTime')))} for r in dis_lic],
    'note': dis_note + ' Licenses under Microsoft’s product names.' + res_note} if dis_lic else {'kicker': lic_kicker, 'note': dis_note}]},
    'disabled-licensed')

# ---------------------------------------------------------------- directory roles
def priv_cell(r):
    html = roles_html(r['_act_priv']) if r['_act_priv'] else 'None active'
    if r['_elig_priv']:
        html += f'<br>Eligible through PIM: {roles_html(r["_elig_priv"])}'
    elif r['_eligible'] is None and not pim_none:
        html += '<br>Eligible through PIM: not collected'
    return html


def capable(r):
    return 'Capable' if r.get('isMfaCapable') is True else 'Not capable'


priv_note = ('Privileged: the role carries Microsoft’s isPrivileged flag. Active: assigned directly to the account. '
             'Eligible: assigned through PIM to the account or to a group it is a direct member of. MFA capable: Microsoft’s '
             'isMfaCapable. High impact: the reason recorded in the collected data.')
if pim_none:
    priv_note += ' PIM eligibility was not collected for this tenant, so eligible roles are not shown.'
elif pim_missing:
    priv_note += f' Enabled members whose PIM eligibility was not collected: {n(pim_missing)}.'
if no_flag:
    priv_note += f' Roles with no isPrivileged value: {n(no_flag)}. They are not counted as privileged.'
if hi_n and not hi_outside:
    priv_note += f' High-impact users: {n(hi_n)}, all listed in this table.'
role_panels = [{'kicker': f'Directory roles, {n(enabled_n)} enabled members', 'bars': bars(role_bars, enabled_n),
                'note': 'Other directory roles: active or eligible roles without Microsoft’s isPrivileged flag.'}]
if priv:
    role_panels.append({
        'kicker': f'Enabled members with a privileged role, active or eligible: {n(priv_n)} of {n(enabled_n)}',
        'cols': [{'key': 'account', 'label': 'Account'}, {'key': 'role', 'label': 'Privileged roles'}, {'key': 'hi', 'label': 'High impact'},
                 {'key': 'mfa', 'label': 'MFA capable'}, {'key': 'pr', 'label': 'Phishing-resistant method'},
                 {'key': 'methods', 'label': 'Methods registered'}, {'key': 'last', 'label': 'Last successful sign-in'}],
        'rows': [{'account': {'text': r['displayName'], 'sub': r.get('jobTitle') or 'No job title'}, 'role': {'html': priv_cell(r)},
                  'hi': impact(r['id']), 'mfa': capable(r), 'pr': 'Yes' if has_pr(r) else 'No', 'methods': esc(method_text(r)),
                  'last': signin(r['_seen'])} for r in priv],
        'note': priv_note})
else:
    role_panels.append({'kicker': f'Enabled members with a privileged role, active or eligible: 0 of {n(enabled_n)}', 'note': priv_note})
if flag_only:
    role_panels.append({'kicker': 'Marked as admin in Microsoft’s registration details, with no active or eligible role on record',
                        'cols': [{'key': 'account', 'label': 'Account'}, {'key': 'hi', 'label': 'High impact'},
                                 {'key': 'mfa', 'label': 'MFA capable'}, {'key': 'last', 'label': 'Last successful sign-in'}],
                        'rows': [{'account': {'text': r['displayName']}, 'hi': impact(r['id']), 'mfa': capable(r), 'last': signin(r['_seen'])}
                                 for r in flag_only]})
R.add({'type': 'panels', 'kicker': 'Directory roles', 'title': 'Privileged role holders', 'cols': 1, 'panels': role_panels},
      'privileged-role-holders')

hi_note = ('High impact: the account has an entry in system.impactSources[] in the collected data. Privileged directory role: '
           'an active, direct role with Microsoft’s isPrivileged flag; roles through a group or eligible through PIM do not count. '
           'Org chart: the configured top-level user or a direct report. Marked by a technician: set by hand.')
if hi_outside:
    def hi_sort(u):
        roles = privileged(flagged(u.get('directoryRoles[].displayName'), u.get('directoryRoles[].isPrivileged')))
        return (0 if u.get('accountEnabled') is True else 1, rank(roles[0]) if roles else len(ROLE_ORDER), u['displayName'].lower(), u['id'])
    hi_rows = []
    for u in sorted(HI.values(), key=hi_sort):
        roles = privileged(flagged(u.get('directoryRoles[].displayName'), u.get('directoryRoles[].isPrivileged')))
        hi_rows.append({'account': {'text': D(u['displayName']), 'sub': D(u['jobTitle']) if u.get('jobTitle') else 'No job title'},
                        'reason': {'text': u['_reason']},
                        'state': {'text': f"{D(u.get('userType') or 'No userType')}, {'enabled' if u.get('accountEnabled') is True else 'disabled'}"},
                        'roles': {'html': roles_html(roles) if roles else 'None'},
                        'last': signin(when(u.get('lastSuccessfulSignInDateTime')))})
    hi_panels = [{'kicker': f'Accounts marked high impact: {n(hi_n)}',
                  'cols': [{'key': 'account', 'label': 'Account'}, {'key': 'reason', 'label': 'Reason'}, {'key': 'state', 'label': 'Account type'},
                           {'key': 'roles', 'label': 'Active privileged roles'}, {'key': 'last', 'label': 'Last successful sign-in'}],
                  'rows': hi_rows,
                  'note': f'Not in the privileged role holders table above: {n(len(hi_outside))}. Enabled first. ' + hi_note}]
else:
    hi_panels = [{'kicker': f'Accounts marked high impact: {n(hi_n)}',
                  'note': ('Every high-impact account is an enabled member with a privileged role, listed under Privileged role holders. '
                           if hi_n else 'No account has an entry in system.impactSources[] in the collected data. ') + hi_note}]
R.add({'type': 'panels', 'kicker': 'High impact', 'title': f'High-impact users: {n(hi_n)}', 'cols': 1, 'panels': hi_panels}, 'high-impact-users')

R.add({'type': 'panels', 'kicker': 'Directory roles', 'title': 'Roles held by disabled accounts', 'cols': 1, 'panels': [{
    'kicker': f'Disabled accounts with directory roles, active or eligible: {n(len(dis_roles))} of {n(disabled_all)}',
    'cols': [{'key': 'account', 'label': 'Disabled account'}, {'key': 'hi', 'label': 'High impact'},
             {'key': 'roles', 'label': 'Active directory roles'}, {'key': 'elig', 'label': 'Eligible through PIM'},
             {'key': 'last', 'label': 'Last successful sign-in'}],
    'rows': [{'account': {'mono': D(r['displayName'])}, 'hi': impact(r['id']), 'roles': {'html': roles_html(r['_act']) if r['_act'] else 'None'},
              'elig': {'html': roles_html(r['_elig']) if r['_elig'] else ('Not collected' if r['_elig'] is None else 'None')},
              'last': signin(when(r.get('lastSuccessfulSignInDateTime')))} for r in dis_roles],
    'note': dis_note} if dis_roles else {
    'kicker': f'Disabled accounts with directory roles, active or eligible: 0 of {n(disabled_all)}', 'note': dis_note}]},
    'disabled-role-holders')

# ---------------------------------------------------------------- sign-in methods
method_bars = [(D(METHOD_NAME.get(m, m)), mcount[m]) for m in morder]
no_pr_kicker = f'Enabled members without a phishing-resistant method: {n(len(no_pr))} of {n(enabled_n)}'
no_mfa_kicker = f'Enabled members not registered for MFA: {n(len(no_mfa))} of {n(enabled_n)}'
no_mfa_note = ('Microsoft’s registration details: isMfaRegistered is not true, so the member has no strong method registered. '
               'Checks: Enabled User Without MFA; Admin Users Without MFA.')
no_pr_note = ('Phishing-resistant here: passkeys of any kind, FIDO2 security keys, Windows Hello for Business, platform credential '
              'and multifactor certificate-based authentication.')
R.add({'type': 'panels', 'kicker': 'Sign-in methods', 'title': f'Sign-in methods of enabled members: {n(enabled_n)}', 'cols': 1, 'panels': [
    {'kicker': f'Enabled members who registered each method, {n(enabled_n)} enabled members',
     'bars': bars(method_bars, enabled_n, data=True) + bars({'No method registered': no_method}, enabled_n),
     'note': 'A member with more than one method counts once for each. Microsoft’s descriptions of the methodsRegistered values, '
             'which are, in the order shown: ' + raw_list(morder) + '.'},
    {'kicker': no_mfa_kicker,
     'cols': [{'key': 'account', 'label': 'Account'}, {'key': 'hi', 'label': 'High impact'}, {'key': 'methods', 'label': 'Methods registered'},
              {'key': 'created', 'label': 'Account created'}, {'key': 'last', 'label': 'Last successful sign-in'}],
     'rows': [{'account': {'text': r['displayName'], 'sub': r.get('jobTitle') or 'No job title'}, 'hi': impact(r['id']),
               'methods': esc(method_text(r)), 'created': R.day(r['_created'], none='No creation date'), 'last': signin(r['_seen'])}
              for r in no_mfa],
     'note': no_mfa_note} if no_mfa else {'kicker': no_mfa_kicker, 'note': no_mfa_note},
    {'kicker': no_pr_kicker,
     'cols': [{'key': 'account', 'label': 'Account'}, {'key': 'hi', 'label': 'High impact'}, {'key': 'methods', 'label': 'Methods registered'},
              {'key': 'created', 'label': 'Account created'}, {'key': 'last', 'label': 'Last successful sign-in'}],
     'rows': [{'account': {'text': r['displayName'], 'sub': r.get('jobTitle') or 'No job title'}, 'hi': impact(r['id']),
               'methods': esc(method_text(r)), 'created': R.day(r['_created'], none='No creation date'), 'last': signin(r['_seen'])}
              for r in no_pr],
     'note': no_pr_note} if no_pr else {'kicker': no_pr_kicker, 'note': no_pr_note}]}, 'sign-in-methods')

# ---------------------------------------------------------------- guests
R.add({'type': 'panels', 'kicker': 'Guests', 'title': f'Guest accounts: {n(guests_n)}', 'cols': 2, 'panels': [
    {'kicker': 'Last successful sign-in', 'bars': bars(gb, guests_n),
     'note': (f'Oldest invitation with no successful sign-in: {R.day(oldest)}. ' if oldest else '')
             + 'Invited: createdDateTime. Guest MFA is not shown: guests register MFA in their home tenant.'},
    {'kicker': f'Guest domains: {n(len(gdom))}',
     'cols': [{'key': 'domain', 'label': 'Domain'}, {'key': 'guests', 'label': 'Guests', 'n': True}],
     'rows': [{'domain': {'mono': D(d)}, 'guests': n(c)} for d, c in gdom_rows]} if gdom else
    {'kicker': 'Guest domains: 0', 'note': 'The tenant has no guest accounts.'},
    {'kicker': f'Invitation state: {n(len(pend))} pending acceptance', 'bars': bars(inv, guests_n),
     'note': 'From externalUserState, which Microsoft sets for guests invited through an invitation: PendingAcceptance (Pending acceptance) '
             'until the guest redeems it, then Accepted. No invitation state: the field is empty, as Microsoft leaves it for other users. '
             'Invited: createdDateTime.' + (f' Oldest invitation pending acceptance: {R.day(oldest_pending)}.' if oldest_pending else '')}
    if guests_n else {'kicker': 'Invitation state', 'note': 'The tenant has no guest accounts.'}]}, 'guests')


# ---------------------------------------------------------------- groups
type_note = ('Type follows Microsoft’s groupTypes, mailEnabled and securityEnabled properties. Dynamic: groupTypes contains '
             'DynamicMembership. Role-assignable: isAssignableToRole is true.')
if 'UnknownGroup' in gtypes:
    type_note += ' Unrecognized type: a combination of the three properties that matches none of the four types.'
type_panels = [{
    'kicker': 'Type, membership type and role assignment',
    'cols': [{'key': 'type', 'label': 'Type'}, {'key': 'groups', 'label': 'Groups', 'n': True},
             {'key': 'assigned', 'label': 'Assigned membership', 'n': True}, {'key': 'dynamic', 'label': 'Dynamic membership', 'n': True},
             {'key': 'rag', 'label': 'Role-assignable', 'n': True}],
    'rows': [{'type': {'text': D(TYPE_NAME[k])}, 'groups': n(v['groups']), 'assigned': n(v['assigned']), 'dynamic': n(v['dynamic']),
              'rag': n(v['roleAssignable'])} for k, v in zip(gtypes, by_type.values())]
            + [{'type': {'text': 'All groups'}, 'groups': n(groups_n), 'assigned': n(assigned_n), 'dynamic': n(dyn_n), 'rag': n(rag_n)}],
    'note': type_note}]
rag_note = ('Directory roles assigned to the group itself, active only. Privileged: the role carries Microsoft’s isPrivileged flag. '
            'Guest members: summary.guestsCount, direct members whose account has userType Guest.')
if rag_no_flag:
    rag_note += f' Roles with no isPrivileged value: {n(rag_no_flag)}. They are not counted as privileged.'
type_panels.append({
    'kicker': f'Role-assignable groups: {n(rag_n)}. With guest members: {n(rag_guests)}',
    'cols': [{'key': 'group', 'label': 'Group'}, {'key': 'members', 'label': 'Direct members', 'n': True},
             {'key': 'guests', 'label': 'Guest members', 'n': True}, {'key': 'priv', 'label': 'Privileged roles', 'n': True},
             {'key': 'roles', 'label': 'Directory roles'}],
    'rows': [{'group': {'mono': D(g['name'])}, 'members': n(g['members']), 'guests': n(g['guests']), 'priv': n(g['priv']),
              'roles': {'html': roles_html(g['roles']) if g['roles'] else 'None'}} for g in rag],
    'note': rag_note} if rag else {'kicker': 'Role-assignable groups: 0', 'note': 'No group has isAssignableToRole set to true.'})
R.add({'type': 'panels', 'kicker': 'Groups', 'title': f'Groups by type: {n(groups_n)}', 'cols': 1, 'panels': type_panels}, 'groups-by-type')

m365_panels = [
    {'kicker': f'Owners per Microsoft 365 group, {n(m365_n)} groups', 'bars': bars(own, m365_n),
     'note': 'From summary.ownersCount: owners of any type, users or service principals.'},
    {'kicker': f'Expiration date, {n(m365_n)} Microsoft 365 groups', 'bars': bars(exp, m365_n),
     'note': f'From expirationDateTime, which Microsoft sets when a group expiration policy applies to the group, counted from {R.as_of}.'}]
if ownerless:
    m365_panels.append({
        'kicker': f'Microsoft 365 groups with no owner: {n(len(ownerless))}',
        'cols': [{'key': 'group', 'label': 'Group'}, {'key': 'members', 'label': 'Direct members', 'n': True},
                 {'key': 'created', 'label': 'Created'}],
        'rows': [{'group': {'mono': D(g['displayName'])}, 'members': n(g['_members']), 'created': R.day(when(g.get('createdDateTime')), none='No creation date')}
                 for g in ownerless[:ROW_CAP]],
        **({'note': first(ownerless, 'by name').strip()} if len(ownerless) > ROW_CAP else {})})
if expiring:
    m365_panels.append({
        'kicker': f'Microsoft 365 groups with an expiration date: {n(len(expiring))}',
        'cols': [{'key': 'group', 'label': 'Group'}, {'key': 'expires', 'label': 'Expires'}, {'key': 'owners', 'label': 'Owners', 'n': True}],
        'rows': [{'group': {'mono': D(g['displayName'])}, 'expires': R.day(when(g['expirationDateTime'])), 'owners': n(g['_owners'])}
                 for g in expiring[:ROW_CAP]],
        'note': 'Sorted by expiration date.' + first(expiring, 'to expire')})
R.add({'type': 'panels', 'kicker': 'Groups', 'title': 'Owners and expiration of Microsoft 365 groups', 'cols': 2, 'panels': m365_panels},
      'm365-owners-expiration')

member_panels = [{'kicker': f'Direct members per group, {n(groups_n)} groups', 'bars': bars(bands, groups_n),
                  'note': 'From summary.membersCount: direct members of any type, guests included. Members of nested groups are not counted.'}]
if with_guests:
    member_panels.append({
        'kicker': f'Groups with guest members: {n(len(with_guests))}',
        'cols': [{'key': 'group', 'label': 'Group'}, {'key': 'type', 'label': 'Type'}, {'key': 'guests', 'label': 'Guest members', 'n': True},
                 {'key': 'members', 'label': 'Direct members', 'n': True}, {'key': 'owners', 'label': 'Owners', 'n': True}],
        'rows': [{'group': {'mono': D(g['displayName'])}, 'type': {'text': D(TYPE_NAME[g['_type']])}, 'guests': n(g['_guests']),
                  'members': n(g['_members']), 'owners': n(g['_owners'])} for g in with_guests[:ROW_CAP]],
        'note': 'From summary.guestsCount: direct members whose account has userType Guest. Sorted by guest members, then by name.'
                + first(with_guests, 'in that order')})
else:
    member_panels.append({'kicker': 'Groups with guest members: 0', 'note': 'No group has a direct member whose account has userType Guest.'})
R.add({'type': 'panels', 'kicker': 'Groups', 'title': 'Direct members and guest members', 'cols': 2, 'panels': member_panels}, 'group-members')

# ---------------------------------------------------------------- part: Conditional Access
CA = 'Conditional Access'
R.add({'type': 'parthead', 'kicker': CA, 'title': f'Conditional Access policies: {n(total)}',
       'sub': 'Policies in Microsoft Entra Conditional Access. Users, groups, directory roles and applications are named by id '
              'from the collected data.'}, 'conditional-access')
R.add({'type': 'panels', 'kicker': CA, 'title': 'Policies by state', 'cols': 1, 'panels': [{
    'kicker': f'Conditional Access policies: {n(total)}',
    'cols': [{'key': 'state', 'label': 'State'}, {'key': 'value', 'label': 'Value in Microsoft Graph'}, {'key': 'n', 'label': 'Policies', 'n': True}],
    'rows': [{'state': {'text': D(label)}, 'value': {'mono': D(s)}, 'n': n(by_state[label])} for s, label in STATE.items()]
            + [{'state': {'text': 'All policies'}, 'value': '', 'n': n(total)}],
    'note': 'Microsoft’s labels for the Enable policy setting. Report-only: Microsoft evaluates the policy at sign-in and logs the '
            'result without enforcing it. Off: the policy has no effect. Off policies are counted here and not listed in this report.'}]},
    'ca-policies-by-state')
R.add({'type': 'panels', 'kicker': CA, 'title': f'Enabled and report-only policies: {n(listed)}', 'cols': 1, 'panels': [{
    'cols': [{'key': 'policy', 'label': 'Policy'}, {'key': 'users', 'label': 'Users'}, {'key': 'res', 'label': 'Target resources'},
             {'key': 'cond', 'label': 'Conditions'}, {'key': 'grant', 'label': 'Grant'}, {'key': 'session', 'label': 'Session'}],
    'rows': TABLE,
    'note': 'Sorted by name. Names come from the collected users, groups, directory roles and service principals by id. A cell '
            'names one or two of a kind and counts longer or mixed lists; the exclusions below name everything a policy excludes. '
            'Device filters read as words: contains for -contains, is for -eq and -in, is not for -ne; a rule that mixes and with or '
            'shows as stored. Named locations and authentication context names are not in the collected data, so Network counts '
            'named locations and a context shows its id.'} if TABLE else {
    'kicker': 'Enabled and report-only policies: 0',
    'note': 'Every Conditional Access policy in the collected data is off.' if total else 'The collected data has no Conditional Access policies.'}]},
    'ca-policy-table')

b = len(CAPPED)
grant_panels = [capped({
    'kicker': 'Grant controls on enabled and report-only policies',
    'cols': [{'key': 'ctl', 'label': 'Grant control'}, {'key': 'on', 'label': 'On', 'n': True},
             {'key': 'ro', 'label': 'Report-only', 'n': True}, {'key': 'pol', 'label': 'Policies'}],
    'rows': [{'ctl': {'text': D(c)}, 'on': n(grants[c]['on']), 'ro': n(grants[c]['reportOnly']),
              'pol': {'html': names_html(grant_use.get(c, []), f'grant: {c}')}} for c in rows_order],
    'note': 'A policy with more than one control counts once for each. Microsoft’s labels.'
            + (' No grant control: the policy sets session controls only.' if grant_use.get('No grant control') else '')}, b)]
if strengths:
    b = len(CAPPED)
    grant_panels.append(capped({
        'kicker': f'Authentication strengths required: {n(len(strengths))}',
        'cols': [{'key': 'name', 'label': 'Authentication strength'}, {'key': 'type', 'label': 'Type'},
                 {'key': 'combos', 'label': 'Allowed combinations'}, {'key': 'pol', 'label': 'Policies'}],
        'rows': [{'name': {'text': s['name']}, 'type': {'text': s['type'], 'sub': f"requirementsSatisfied: {s['satisfied']}"},
                  'combos': {'html': '<br>'.join(esc(c) for c in s['combos']) or 'None collected'},
                  'pol': {'html': names_html(s['policies'], f"strength: {s['name']}")}}
                 for s in sorted(strengths.values(), key=lambda s: key(s['name']))],
        'note': 'Allowed combinations as Microsoft reports them; a sign-in satisfies the strength with any one of them. A method also '
                'needs the tenant’s authentication methods policy to allow it, and that policy is not in the collected data.'}, b))
else:
    grant_panels.append({'kicker': 'Authentication strengths required: 0',
                         'note': 'No enabled or report-only policy requires an authentication strength.'})
R.add({'type': 'panels', 'kicker': CA, 'title': 'Grant controls and authentication strengths', 'cols': 1, 'panels': grant_panels},
      'ca-grant-controls')


def names_list(names_, what):
    if len(names_) > NAME_CAP:
        CAPPED[what] = len(names_) - NAME_CAP
        names_ = names_[:NAME_CAP] + [f'and {n(len(names_) - NAME_CAP)} more']
    return '<br>'.join(esc(x) for x in names_) if names_ else 'None'


def group_cells(p):
    out = []
    for gid in p.get('conditions.users.excludeGroups[]') or []:
        name = group_name(gid)
        out.append(f'{name} ({n(G[gid]["_members"])} direct member{"" if G[gid]["_members"] == 1 else "s"})' if gid in G else name)
    return sorted(out, key=key)


def guest_cell(p, a):
    types = a['guest or external user type']
    if not types:
        return 'None'
    kind = p.get('conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind')
    return '<br>'.join([esc(t) for t in types] + ([esc(D(TENANTS.get(kind, kind)))] if kind else []))


b = len(CAPPED)
workload = any(a['workload identity'] for _, a in EXCL)
excl_panels = [capped({
    'kicker': f'Enabled and report-only policies with exclusions: {n(len(EXCL))} of {n(listed)}',
    'cols': [{'key': 'policy', 'label': 'Policy'}, {'key': 'users', 'label': 'Excluded users'}, {'key': 'groups', 'label': 'Excluded groups'},
             {'key': 'roles', 'label': 'Excluded directory roles'}, {'key': 'guests', 'label': 'Excluded guest or external users'}]
            + ([{'key': 'wid', 'label': 'Excluded workload identities'}] if workload else [])
            + [{'key': 'res', 'label': 'Excluded resources'}],
    'rows': [{'policy': {'text': p['displayName'], **({'status': 'Report-only'} if p['id'] in RO else {})},
              'users': {'html': names_list(a['user'], f'excluded users: {p["displayName"]}')},
              'groups': {'html': names_list(group_cells(p), f'excluded groups: {p["displayName"]}')},
              'roles': {'html': names_list(a['directory role'], f'excluded roles: {p["displayName"]}')},
              'guests': {'html': guest_cell(p, a)},
              'wid': {'html': names_list(a['workload identity'], f'excluded workload identities: {p["displayName"]}')},
              'res': {'html': names_list(a['resource'], f'excluded resources: {p["displayName"]}')}} for p, a in EXCL],
    'note': 'Names by id from the collected users, groups, directory roles and service principals. Disabled: accountEnabled is '
            'false. Direct members: summary.membersCount, members of any type; members of nested groups are not counted.'}, b)] if EXCL else [{
    'kicker': f'Enabled and report-only policies with exclusions: 0 of {n(listed)}', 'note': 'No enabled or report-only policy excludes anything.'}]
x_note = ('From the per-account policy evaluation in the collected data: an enabled policy that requires MFA, by Require '
          'multifactor authentication or an authentication strength that satisfies MFA, includes the account and excludes it, and '
          'no such policy applies to it. The evaluation reads users, groups, directory roles and guest types; applications, '
          'networks, platforms, client apps, device filters and risk are not part of it. The finding Enabled User Excluded From '
          'MFA Policy selects accounts by the same evaluation.')
x_kicker = f'Enabled members excluded from every enabled MFA policy that includes them: {n(excluded_n)} of {n(enabled_n)}'
excl_panels.append({
    'kicker': x_kicker,
    'cols': [{'key': 'acct', 'label': 'Account'}, {'key': 'hi', 'label': 'High impact'}, {'key': 'pol', 'label': 'Enabled MFA policies that exclude it'},
             {'key': 'via', 'label': 'Excluded through'}],
    'rows': [{'acct': {'text': u['displayName'], 'sub': u.get('userPrincipalName') or ''}, 'hi': impact(u['id']),
              'pol': {'html': '<br>'.join(esc(a) for a, _ in v)},
              'via': {'html': esc(v[0][1]) if len({w for _, w in v}) == 1 else '<br>'.join(f'{esc(w)} ({esc(a)})' for a, w in v)}}
             for u, v in x_rows],
    'note': x_note} if x_rows else {'kicker': x_kicker, 'note': 'No enabled member account matches. ' + x_note})
R.add({'type': 'panels', 'kicker': CA, 'title': 'What each policy excludes', 'cols': 1, 'panels': excl_panels}, 'ca-exclusions')

df_kicker = f'Enabled and report-only policies with a device filter: {n(len(DF_ROWS))} of {n(listed)}'
R.add({'type': 'panels', 'kicker': CA, 'title': 'Device filters', 'cols': 1, 'panels': [{
    'kicker': df_kicker,
    'cols': [{'key': 'policy', 'label': 'Policy'}, {'key': 'words', 'label': 'Filter'}, {'key': 'rule', 'label': 'Rule as stored'}],
    'rows': [{'policy': {'text': p['displayName'], **({'status': 'Report-only'} if p['id'] in RO else {})},
              'words': {'text': words or 'Mixes and with or, or uses another operator: see the rule', 'sub': label},
              'rule': {'mono': D(rule)}} for p, label, words, rule in DF_ROWS],
    'note': 'The label under each filter is Microsoft’s name for the filter mode.'} if DF_ROWS else {
    'kicker': df_kicker, 'note': 'No enabled or report-only policy sets a device filter.'}]}, 'ca-device-filters')

# ---------------------------------------------------------------- footer
R.footer(f'Read-only collection on {R.as_of}. Values come from tenant data queries over users, groups, directory roles, '
         'the license products the tenant subscribes to, Conditional Access policies and service principals, finding counts and Microsoft Secure Score: the same queries for '
         'every tenant, read from one collection run.',
         'Enabled members are accounts with userType Member and accountEnabled true. Sign-in dates use '
         'lastSuccessfulSignInDateTime; Never signed in means the field is empty. MFA capable is Microsoft’s isMfaCapable. '
         'Privileged roles carry Microsoft’s isPrivileged flag. Active roles are assigned directly; eligible roles come from PIM. '
         'High impact: the account has an entry in system.impactSources[] in the collected data. Group types follow Microsoft’s '
         'groupTypes, mailEnabled and securityEnabled. Direct members are members of any type: users, guests, devices, service '
         'principals and groups. On, Report-only and Off are Microsoft’s labels for a policy’s state; a policy requiring MFA has '
         'Require multifactor authentication or an authentication strength.',
         'Active roles an account holds through a role-assignable group, which show on the group. Group membership or '
         'ownership eligible through PIM for Groups. Guest MFA, which guests register in their home tenant. Members of '
         'nested groups. Off Conditional Access policies, which are counted by state only. Named locations, security defaults '
         'and the tenant’s authentication methods policy, which are not in the collected data. Sign-ins and the policies that '
         'applied to them.' + (' Roles eligible through PIM, which were not collected for this tenant.' if pim_none else ''))
if CAPPED:
    fact('ca.names.cap', NAME_CAP, 'recipe constant')
    fact('ca.names.not_shown', CAPPED, 'policies + users + groups')
for kind, ids in sorted(UNRESOLVED.items()):
    print(f'note: {len(ids)} {kind} not in collected data: {sorted(ids)}')
fact('ca.names.not_in_collected_data', {k: len(v) for k, v in sorted(UNRESOLVED.items())}, 'users + groups + directory_roles + service_principals')
R.write()
