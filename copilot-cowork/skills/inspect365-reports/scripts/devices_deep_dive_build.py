"""Devices report recipe, v0.3.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/devices_deep_dive/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

<run-dir>/run.json names the tenant and date; <run-dir>/inputs/<id>.json holds the response to each query in
queries.json, saved exactly as returned, all from one collection run. The title band shows the working set (device
records, corporate, active corporate). After the device findings and Microsoft Secure Score, every device finding check
has a data view over the devices it applies to, with zeros shown: coverage across Entra, Intune and Defender (what each
source misses first), high-impact devices, Defender exposure and antivirus, Intune compliance, encryption and BitLocker
recovery keys, firewall, Windows edition and Windows 11 readiness, Intune check-in by join type, Windows Autopilot, and an
inventory of active corporate devices. Compliance lists the settings that failed on each device (2026-10-14). Cloud PCs,
found by Microsoft's own filter rule, count as encrypted by Windows 365 rather than Not encrypted (2026-10-14).
Every section is always present and has an id that run.json "omit" can name.
A state a source reports shows Microsoft's label with the source's value beneath. A device whose primary user is high
impact, or that a technician marked, carries a High impact mark with the reason, and those devices list first.
Tables show device fields and never a label inferred from a device name. The same inputs always produce the same bytes.
"""
import pathlib, sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import IMPACT_REASON, Report, esc, n, width  # noqa: E402

R = Report(__file__, 'devices-deep-dive', '0.3.0', 'Devices report')
D, fact = R.D, R.fact

# ---------------------------------------------------------------- Microsoft's values in Microsoft's order, with the labels its portals show
OWNERSHIP = ['Corporate', 'Personal', 'Unknown']
JOIN = ['Entra joined', 'Entra hybrid joined', 'Entra registered', 'Unknown']
PROFILE = {'RegisteredDevice': 'Registered device', 'Shared': 'Shared', 'SecureVM': 'Secure VM', 'Printer': 'Printer',
           'IoT': 'IoT'}                                                                             # Entra deviceProfileType
EXPOSURE = ['High', 'Medium', 'Low', 'None']                                                         # Defender exposureLevel
RISK = ['High', 'Medium', 'Low', 'Informational', 'None']                                            # Defender riskScore
SENSOR = {'Active': 'Active', 'Inactive': 'Inactive', 'ImpairedCommunication': 'Impaired communications',
          'NoSensorData': 'No sensor data', 'NoSensorDataImpairedCommunication': 'No sensor data, impaired communications'}
AV_MODE = {'Active': 'Active', 'Passive': 'Passive', 'Disabled': 'Disabled', 'Other': 'Others',
           'EDRBlocked': 'EDR in block mode', 'PassiveAudit': 'Passive audit'}
CURRENT = {'True': 'Up to date', 'False': 'Out of date', 'Unknown': 'No data available'}          # Defender avIs*UpToDate
COMPONENTS = [('Signature', 'defenderDevice.deviceAvInfo.avIsSignatureUpToDate'),
              ('Engine', 'defenderDevice.deviceAvInfo.avIsEngineUpToDate'),
              ('Platform', 'defenderDevice.deviceAvInfo.avIsPlatformUpToDate')]
COMPLIANCE = {'Compliant': 'Compliant', 'Noncompliant': 'Not compliant', 'InGracePeriod': 'In grace period',
              'Not Evaluated': 'Not evaluated', 'Unknown': 'Unknown', 'Conflict': 'Conflict', 'Error': 'Error',
              'ConfigManager': 'See ConfigMgr'}                                                      # Intune compliantState
POLICY_STATE = {'compliant': 'Compliant', 'remediated': 'Remediated', 'nonCompliant': 'Not compliant', 'error': 'Error',
                'conflict': 'Conflict', 'unknown': 'Unknown', 'notApplicable': 'Not applicable', 'notAssigned': 'Not assigned'}
ENCRYPTION = {'encrypted': 'Encrypted', 'notEncrypted': 'Not encrypted'}                          # Intune encryption report
READINESS = {'ready': 'Ready', 'notReady': 'Not ready'}
BITLOCKER = {'success': 'Success', 'noUserConsent': 'User never gave consent for encryption',       # Graph advancedBitLockerState
             'osVolumeUnprotected': 'The OS volume is unprotected',
             'osVolumeTpmRequired': 'TPM not used for protection of OS volume, but is required by policy',
             'osVolumeTpmOnlyRequired': 'TPM only protection not used for OS volume, but is required by policy',
             'osVolumeTpmPinRequired': 'TPM+PIN protection not used for OS volume, but is required by policy',
             'osVolumeTpmStartupKeyRequired': 'TPM+Startup Key protection not used for OS volume, but is required by policy',
             'osVolumeTpmPinStartupKeyRequired': 'TPM+PIN+Startup Key not used for OS volume, but is required by policy',
             'osVolumeEncryptionMethodMismatch': 'Encryption method of OS volume is different than that set by policy',
             'recoveryKeyBackupFailed': 'Recovery key backup failed', 'fixedDriveNotEncrypted': 'A fixed drive is unprotected',
             'fixedDriveEncryptionMethodMismatch': 'Encryption method of fixed drive is different than that set by policy',
             'loggedOnUserNonAdmin': 'Logged on user is non-admin', 'windowsRecoveryEnvironmentNotConfigured': 'WinRE is not configured',
             'tpmNotAvailable': 'TPM is not available for BitLocker', 'tpmNotReady': 'TPM is not ready for BitLocker',
             'networkError': 'Network not available'}
ELIGIBILITY = {'upgraded': 'Upgraded', 'capable': 'Capable', 'notCapable': 'Not capable', 'unknown': 'Unknown'}  # Endpoint Analytics
FIREWALL = ['Enabled', 'Disabled', 'Limited', 'Temporarily Disabled (default)', 'Not applicable']  # Intune firewall report, codes 0 to 4
AUTOPILOT = {'enrolled': 'Enrolled', 'notContacted': 'Not contacted', 'pendingReset': 'Pending reset', 'failed': 'Failed',
             'blocked': 'Blocked', 'unknown': 'Unknown'}                                             # Autopilot enrollmentState
KEY = {'True': 'Key held in Entra ID', 'False': 'No key in Entra ID'}
WFA = 'intuneDevice.workFromAnywhereStatus.'
CHECKS = [('processor64BitCheckFailed', 'Processor 64-bit'), ('processorCoreCountCheckFailed', 'Processor core count'),
          ('processorFamilyCheckFailed', 'Processor family'), ('processorSpeedCheckFailed', 'Processor speed'),
          ('ramCheckFailed', 'RAM'), ('storageCheckFailed', 'Storage'), ('tpmCheckFailed', 'TPM'),
          ('secureBootCheckFailed', 'Secure Boot'), ('osCheckFailed', 'Operating system')]
SOURCES = [('Entra', 'entraDeviceId'), ('Intune', 'intuneDeviceId'), ('Defender', 'defenderDeviceId')]
COMBOS = [('Entra', 'Intune', 'Defender'), ('Entra', 'Intune'), ('Entra', 'Defender'), ('Intune', 'Defender'),
          ('Entra',), ('Intune',), ('Defender',), ()]
ALL3 = 'Entra, Intune and Defender'
ABSENT = {'Entra': 'No active corporate device has an Entra device record in the collected data.',
          'Intune': 'No active corporate device is enrolled in Intune in the collected data.',
          'Defender': 'No active corporate device is onboarded to Microsoft Defender for Endpoint in the collected data.'}
# Each device finding check (registry id) and the section that shows its data. The registry gives the names.
CHECK = {'risk': '63548599-5364-439a-a534-956dd9af51aa', 'exposure': 'aa77213d-44f7-4228-913f-c415787cbfed',
         'home': 'f8303954-ec21-43ee-810d-5dfc570a33d0', 'win11': 'a6729443-1156-4e04-b5f4-d48d1ce76f9d',
         'firewall': '8b45706a-5c24-4c4f-ab86-c30d835b203c', 'avCurrent': '7a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5e',
         'hybridIntune': '5745c3e7-bf8b-4da4-8a87-37f29e9709bb', 'sensor': 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
         'avMode': 'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e', 'notIntune': 'c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f',
         'notDefender': 'd4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a', 'stale': 'e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b',
         'encryption': 'f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0c', 'noncompliant': '190e8fa2-1752-4dfb-ba9d-81cc58ace325',
         'recoveryKey': '66234f94-65aa-40b6-9347-ccc77dccd600', 'autopilot': 'c0d4ed1a-bb76-4b9c-b036-6d437d35f36c'}
# Labels for a missing value; they come last in a tally and draw in the neutral mark.
QUIET = ['Not reported', 'No contact recorded', 'No encryption report', 'No firewall report', 'No Work From Anywhere record',
         'No check-in recorded', 'No Intune record', 'Not onboarded', 'No linked record']
WIN11 = D('Windows 11')
MODELS_SHOWN = 15
# Windows 365 Cloud PCs (2026-10-14). Learn, "Create a filter for Cloud PCs": Microsoft's filter for all Cloud PCs matches an
# Intune model that contains "Cloud PC" or "Windows 365". Learn, "Data encryption in Windows 365": Cloud PC disks are encrypted
# with Azure Storage server-side encryption and host-based encryption, and BitLocker isn't supported on Cloud PCs, so Intune's
# encryption report shows them Not encrypted.
CLOUD_PC_MODEL = ('Cloud PC', 'Windows 365')
CLOUD_PC = 'Cloud PC, encrypted by Windows 365'
FAILED = ['nonCompliant', 'error', 'conflict']                                                      # a setting that failed
MB_PER_GB = 1024                                                                                    # Intune reports storage in MB


# ---------------------------------------------------------------- helpers
def g(r, f):
    """A field as a string, or None when it is missing or empty."""
    v = r.get(f)
    return None if v is None or v == '' else str(v)


def tally(rows, get, order=(), always=()):
    """Counts by value: values in Microsoft's order first (those in always even at zero), then other values by
    count, then the missing-value labels in QUIET order."""
    c = Counter(get(r) for r in rows)
    out = {v: c.pop(v, 0) for v in order if v in always or c.get(v)}
    quiet = {v: c.pop(v) for v in QUIET if v in c}
    out.update(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))
    out.update(quiet)
    return out


def bars(counts, of, labels=None, data=True):
    """Bars for a tally. labels maps a source value to Microsoft's label; data=False marks fixed labels of our own."""
    out = []
    for k, v in counts.items():
        quiet = k in QUIET
        text = k if quiet or labels is None else labels.get(k, k)
        out.append({'label': esc(text if quiet or not data else D(text)), 'value': n(v), 'pct': width(v, of),
                    'color': 'var(--neutral-mark)' if quiet else 'var(--series-1)'})
    return out


def values(source, keys, labels):
    """The source's own values behind the labels shown, for a panel note."""
    pairs = [(k, labels[k]) for k in keys if k in labels and labels[k] != k]
    return f'{source} values: ' + ', '.join(f'{esc(D(k))} ({esc(label)})' for k, label in pairs) + '.' if pairs else ''


def st(labels, raw, source, missing):
    """A table cell for a state a source reports: Microsoft's label, with the source's value beneath when they differ."""
    if raw is None:
        return {'text': missing}
    label = labels.get(raw, raw) if labels else raw
    return R.state(label, raw, source) if label != raw else {'text': D(raw)}


def defender(r, f, labels=None):
    return st(labels, g(r, f), 'Defender', 'Not reported') if r.get('defenderDeviceId') else {'text': 'Not onboarded'}


def intune(r, f, labels=None, missing='Not reported'):
    return st(labels, g(r, f), 'Intune', missing) if r.get('intuneDeviceId') else {'text': 'No Intune record'}


def high(r):
    return bool(r.get('system.impactSources[].type'))


def reason(r):
    """Why the device is high impact, in the product's terms: its owner's rule, or a technician's mark."""
    types = r.get('system.impactSources[].type') or []
    rules = sorted({IMPACT_REASON.get(x, D(x)) for x in r.get('system.impactSources[].sourceRule') or [] if x})
    out = []
    if 'inherited' in types:
        out.append(IMPACT_REASON['inherited'] + (f' ({", ".join(rules)})' if rules else ''))
    if 'manualAssignment' in types:
        out.append(IMPACT_REASON['manualAssignment'])
    out += [IMPACT_REASON.get(t, D(t)) for t in sorted(set(types) - {'inherited', 'manualAssignment'})]
    return '; '.join(out)


def device(r, mark=True):
    """The device name with its primary user beneath; a high-impact device adds the mark (unless the table lists only those)
    and the reason."""
    owner = D(r['owner']) if r.get('owner') else 'No primary user'
    if not high(r):
        return {'mono': D(r['displayName']), 'sub': owner}
    return {'mono': D(r['displayName']), **({'status': 'High impact'} if mark else {}), 'sub': f'{owner} · {reason(r)}'}


def name_key(r):
    return (not high(r), r['displayName'].lower(), r['id'])


def combo(r):
    return tuple(s for s, f in SOURCES if r.get(f))


def combo_label(c):
    if len(c) == 3:
        return ALL3
    if len(c) == 2:
        return f'{c[0]} and {c[1]} only'
    return f'{c[0]} only' if c else 'No linked record'


def model(r):
    return g(r, 'entraDevice.model') or g(r, 'intuneDevice.model')


def maker(r):
    return g(r, 'entraDevice.manufacturer') or g(r, 'intuneDevice.manufacturer')


def system(r):
    """Operating system and version as one data string, so a bare version such as 12 is never a data string on its own."""
    os_, ver = g(r, 'operatingSystem'), g(r, 'operatingSystemVersion')
    return {'text': D(' '.join(x for x in (os_, ver) if x)) if os_ or ver else 'Not reported'}


def hardware(m, k):
    return {'text': D(m.strip()) if m else 'Not reported', 'sub': D(k.strip()) if k else None}


def cloud_pc(r):
    """A Windows 365 Cloud PC by Microsoft's filter rule: the Intune model contains Cloud PC or Windows 365."""
    m = (g(r, 'intuneDevice.model') or '').casefold()
    return any(s.casefold() in m for s in CLOUD_PC_MODEL)


def failed_settings(r):
    """Compliance settings Intune reports as nonCompliant, error or conflict on the device: (label, setting name, state)."""
    cols = [r.get(f'intuneDevice.compliancePolicies[].settings[].{k}') or [] for k in ('displayName', 'name', 'state')]
    if len({len(c) for c in cols}) > 1:
        sys.exit(f'compliance setting arrays on {r["displayName"]} differ in length; run the query again')
    return sorted({(lab or nm, nm, s) for lab, nm, s in zip(*cols) if s in FAILED}, key=lambda x: (x[0].lower(), x[1], x[2]))


def gb(mb):
    """Intune's MB as GB to one decimal place, or None."""
    return None if mb in (None, '') else round(float(mb) / MB_PER_GB, 1)


def contact(r, id_field, date_field, no_record, no_date):
    return R.day(R.when(r.get(date_field)), none=no_date) if r.get(id_field) else no_record


def entra_seen(r):
    return contact(r, 'entraDeviceId', 'entraDeviceLastContact', 'No Entra record', 'Never signed in')


def intune_seen(r):
    return contact(r, 'intuneDeviceId', 'intuneDeviceLastContact', 'No Intune record', 'No check-in recorded')


def defender_seen(r):
    return contact(r, 'defenderDeviceId', 'defenderDeviceLastContact', 'Not onboarded', 'No report recorded')


def build_of(r):
    v = g(r, 'operatingSystemVersion')
    return D('.'.join(v.split('.')[:3])) if v else 'Not reported'


def order_of(seq, v):
    return seq.index(v) if v in seq else len(seq)


def checks(*keys):
    """The finding checks a section shows data for, by their registry names."""
    names = [esc(D(DEFS[CHECK[k]]['displayName'])) for k in keys if CHECK[k] in DEFS]
    return ('Finding checks: ' if len(names) > 1 else 'Finding check: ') + ', '.join(names) + '.' if names else None


def section(kicker, title, panels, id, cols=1, sub=None):
    s = {'type': 'panels', 'kicker': kicker, 'title': title, 'cols': cols, 'panels': panels}
    if sub:
        s['sub'] = sub
    R.add(s, id)


def table(kicker, cols, rows, note, empty):
    """A device list, or the plain statement that it is empty."""
    if not rows:
        return {'kicker': kicker, 'note': empty}
    return {'kicker': kicker, 'cols': cols, 'rows': rows, 'note': note}


DEFS = {d['id']: d for d in R.IN['definitions']['definitions'] if d['type'] == 'Device'}
unmapped = sorted(d['displayName'] for i, d in DEFS.items() if i not in CHECK.values())
if unmapped:
    print(f'warning: device checks with no data view in this recipe: {unmapped}', file=sys.stderr)

# ---------------------------------------------------------------- device records
own, act = R.buckets('devices_by_ownership'), R.buckets('corporate_by_activity')
records = fact('devices.records', R.total('devices_by_ownership'), 'devices_by_ownership')
unclassified = R.IN['devices_by_ownership'].get('nullOrMissingCount', 0)
by_owner = fact('devices.byOwnership', {k: own[k] for k in OWNERSHIP if k in own}
                | dict(sorted(((k, v) for k, v in own.items() if k not in OWNERSHIP), key=lambda kv: (-kv[1], kv[0])))
                | ({'Not reported': unclassified} if unclassified else {}), 'devices_by_ownership')
corporate = fact('devices.corporate', R.total('corporate_by_activity'), 'corporate_by_activity')
by_activity = fact('corporate.byActivity', {'Active': act.get('False', 0), 'Inactive': act.get('True', 0)}, 'corporate_by_activity')

A = sorted(R.rows('corporate_active'), key=lambda r: (r['displayName'].lower(), r['id']))
I = sorted(R.rows('corporate_inactive'), key=lambda r: (r['displayName'].lower(), r['id']))
if len(A) != by_activity['Active'] or len(I) != by_activity['Inactive']:
    sys.exit(f'device lists ({len(A)} active, {len(I)} inactive) do not match corporate_by_activity {by_activity}; run the queries again')
active = fact('active.devices', len(A), 'corporate_active')

AGE = [(None, 90, '90 days or fewer'), (91, 365, '91 to 365 days'), (366, None, 'More than 365 days')]
ages = [R.age(R.when(r.get('lastContact'))) for r in I]
age_rows = [{'from': lo, 'to': hi, 'devices': sum(1 for a in ages if a is not None and (lo is None or a >= lo) and (hi is None or a <= hi))}
            for lo, hi, _ in AGE] + [{'from': None, 'to': None, 'devices': sum(1 for a in ages if a is None)}]
fact('inactive.daysSinceLastContact', age_rows, 'corporate_inactive')
inactive_age = {label: row['devices'] for (_, _, label), row in zip(AGE, age_rows)}
if age_rows[-1]['devices']:
    inactive_age['No contact recorded'] = age_rows[-1]['devices']
inactive_src = fact('inactive.sources', tally(I, lambda r: combo_label(combo(r)), [combo_label(c) for c in COMBOS]), 'corporate_inactive')

# ---------------------------------------------------------------- active corporate devices
by_os = fact('active.byOperatingSystem', tally(A, lambda r: g(r, 'operatingSystem') or 'Not reported'), 'corporate_active')
by_join = fact('active.byJoinType', tally(A, lambda r: g(r, 'joinType') or 'Not reported', JOIN), 'corporate_active')
by_profile = fact('active.byEntraProfileType', tally(A, lambda r: g(r, 'entraDevice.profileType') or 'Not reported', list(PROFILE)),
                  'corporate_active')
models = sorted(Counter((maker(r) or '', model(r) or '') for r in A).items(), key=lambda kv: (-kv[1], kv[0][0].lower(), kv[0][1].lower()))
fact('active.models', {f'{k} | {m}': c for (k, m), c in models}, 'corporate_active')
shown, rest = models[:MODELS_SHOWN], models[MODELS_SHOWN:]
fact('active.modelsShown', {'shown': len(shown), 'models': len(models), 'otherModels': len(rest),
                            'otherDevices': sum(c for _, c in rest)}, 'corporate_active')

# ---------------------------------------------------------------- coverage: what each source misses
seen = {r['id']: combo(r) for r in A}
by_source = fact('coverage.bySource', {s: sum(1 for r in A if r.get(f)) for s, f in SOURCES}, 'corporate_active')
MISS = [('No Entra device record', lambda r: not r.get('entraDeviceId')),
        ('Not enrolled in Intune', lambda r: not r.get('intuneDeviceId')),
        ('Not onboarded to Defender', lambda r: not r.get('defenderDeviceId')),
        ('In neither Intune nor Defender', lambda r: not r.get('intuneDeviceId') and not r.get('defenderDeviceId'))]
missing = fact('coverage.missing', {label: sum(1 for r in A if test(r)) for label, test in MISS}, 'corporate_active')
gap_any = fact('coverage.missingIntuneOrDefender', sum(1 for r in A if not r.get('intuneDeviceId') or not r.get('defenderDeviceId')),
               'corporate_active')
by_combo = fact('coverage.byCombination', {combo_label(c): k for c in COMBOS if (k := sum(1 for r in A if seen[r['id']] == c))},
                'corporate_active')
absent = [s for s, _ in SOURCES if A and not by_source[s]]
watched = [(s, f) for s, f in SOURCES if by_source[s]]
gaps = sorted((r for r in A if any(not r.get(f) for _, f in watched)),
              key=lambda r: (not high(r), COMBOS.index(seen[r['id']]), r['displayName'].lower(), r['id']))
fact('coverage.missingFromASource', [r['displayName'] for r in gaps], 'corporate_active')

# ---------------------------------------------------------------- high impact
crit_input = R.IN['critical_software_by_device']
crit = R.buckets('critical_software_by_device')
crit_cut = crit_input.get('omittedBucketCount', 0)
fact('vulnerabilities.criticalSoftwareByDevice', {'devices': len(crit), 'omittedDevices': crit_cut, 'byDevice': crit},
     'critical_software_by_device')


def critical(r):
    """Software records Defender lists on the device whose highest-rated CVE is Critical, or None when not known."""
    if not r.get('defenderDeviceId'):
        return None
    return crit.get(r['id'], None if crit_cut else 0)


def critical_cell(r):
    if not r.get('defenderDeviceId'):
        return {'text': 'Not onboarded'}
    c = critical(r)
    return {'text': 'Not counted'} if c is None else n(c)


HI = sorted((r for r in A if high(r)),
            key=lambda r: (order_of(EXPOSURE, g(r, 'defenderDevice.exposureLevel')), -(critical(r) or 0),
                           order_of(RISK, g(r, 'defenderDevice.riskScore')), r['displayName'].lower(), r['id']))
by_reason = fact('highImpact.byReason', dict(sorted(Counter(reason(r) for r in HI).items())), 'corporate_active')
fact('highImpact.devices', [{'device': r['displayName'], 'reason': reason(r), 'exposureLevel': g(r, 'defenderDevice.exposureLevel'),
                             'criticalSoftware': critical(r)} for r in HI], 'corporate_active + critical_software_by_device')
hi_onboarded = fact('highImpact.onboarded', sum(1 for r in HI if r.get('defenderDeviceId')), 'corporate_active')
hi_exposed = fact('highImpact.exposureHigh', sum(1 for r in HI if g(r, 'defenderDevice.exposureLevel') == 'High'), 'corporate_active')
hi_critical = fact('highImpact.withCriticalSoftware', sum(1 for r in HI if critical(r)), 'corporate_active + critical_software_by_device')

# ---------------------------------------------------------------- Defender exposure, risk and antivirus
DF = [r for r in A if r.get('defenderDeviceId')]
onboarded = fact('defender.onboarded', len(DF), 'corporate_active')
exposure = fact('defender.exposureLevel', tally(DF, lambda r: g(r, 'defenderDevice.exposureLevel') or 'Not reported', EXPOSURE, EXPOSURE),
                'corporate_active')
risk = fact('defender.riskScore', tally(DF, lambda r: g(r, 'defenderDevice.riskScore') or 'Not reported', RISK, RISK), 'corporate_active')
exposed = sorted((r for r in DF if g(r, 'defenderDevice.exposureLevel') == 'High' or g(r, 'defenderDevice.riskScore') in ('High', 'Medium')),
                 key=lambda r: (not high(r), order_of(EXPOSURE, g(r, 'defenderDevice.exposureLevel')),
                                order_of(RISK, g(r, 'defenderDevice.riskScore')), r['displayName'].lower(), r['id']))
fact('defender.highExposureOrRisk', [r['displayName'] for r in exposed], 'corporate_active')

sensor = fact('antivirus.sensorHealth', tally(DF, lambda r: g(r, 'defenderDevice.healthStatus') or 'Not reported', list(SENSOR), list(SENSOR)),
              'corporate_active')
av_mode = fact('antivirus.mode', tally(DF, lambda r: g(r, 'defenderDevice.deviceAvInfo.avModeName') or 'Not reported', list(AV_MODE)),
               'corporate_active')
components = fact('antivirus.upToDate', {name: tally(DF, lambda r, f=f: g(r, f) or 'Not reported', list(CURRENT), list(CURRENT))
                                         for name, f in COMPONENTS}, 'corporate_active')
ROLLUP = ['All three up to date', 'One or more out of date', 'One or more with no data available']


def av_rollup(r):
    states = [g(r, f) for _, f in COMPONENTS]
    if any(s is None for s in states):
        return 'Not reported'
    if 'False' in states:
        return ROLLUP[1]
    return ROLLUP[0] if all(s == 'True' for s in states) else ROLLUP[2]


av_devices = fact('antivirus.componentsByDevice', tally(DF, av_rollup, ROLLUP, ROLLUP), 'corporate_active')
av_flag = sorted((r for r in DF if g(r, 'defenderDevice.healthStatus') != 'Active' or g(r, 'defenderDevice.deviceAvInfo.avModeName') != 'Active'
                  or any(g(r, f) != 'True' for _, f in COMPONENTS)),
                 key=lambda r: (not high(r), order_of(list(SENSOR), g(r, 'defenderDevice.healthStatus')), r['displayName'].lower(), r['id']))
fact('antivirus.notActiveOrNotCurrent', [r['displayName'] for r in av_flag], 'corporate_active')

# ---------------------------------------------------------------- Intune compliance
IN_ = [r for r in A if r.get('intuneDeviceId')]
enrolled = fact('intune.enrolled', len(IN_), 'corporate_active')
compliance = fact('compliance.state', tally(A, lambda r: (g(r, 'intuneCompliantState') or 'Not reported') if r.get('intuneDeviceId')
                                            else 'No Intune record', list(COMPLIANCE)), 'corporate_active')
policies = {}
for r in A:
    for name, state in sorted(set(zip(r.get('intuneDevice.compliancePolicies[].name') or [],
                                      r.get('intuneDevice.compliancePolicies[].policyState') or []))):
        p = policies.setdefault(name, {'devices': 0, 'states': Counter()})
        p['devices'] += 1
        p['states'][state] += 1
policy_rows = sorted(policies.items(), key=lambda kv: (-kv[1]['devices'], kv[0].lower()))
fact('compliance.policies', {k: {'devices': v['devices'], **dict(sorted(v['states'].items()))} for k, v in policy_rows}, 'corporate_active')
present = {s for _, v in policy_rows for s in v['states']}
policy_states = [s for s in POLICY_STATE if s in present] + sorted(present - set(POLICY_STATE))
not_compliant = sorted((r for r in IN_ if g(r, 'intuneCompliantState') != 'Compliant'),
                       key=lambda r: (not high(r), order_of(list(COMPLIANCE), g(r, 'intuneCompliantState')), r['displayName'].lower(), r['id']))
fact('compliance.notCompliant', [r['displayName'] for r in not_compliant], 'corporate_active')
failed = {r['id']: failed_settings(r) for r in IN_}
fact('compliance.failedSettingsByDevice', {r['displayName']: [x[1] for x in failed[r['id']]] for r in IN_ if failed[r['id']]}, 'corporate_active')
setting_counts = Counter(key for r in IN_ for key in {(x[0], x[1]) for x in failed[r['id']]})       # once per device
setting_rows = sorted(setting_counts.items(), key=lambda kv: (-kv[1], kv[0][0].lower(), kv[0][1]))
fact('compliance.failedSettings', {nm: c for (_, nm), c in setting_rows}, 'corporate_active')
failing_devices = fact('compliance.devicesWithFailedSettings', sum(1 for r in IN_ if failed[r['id']]), 'corporate_active')


def policy_text(r):
    pairs = sorted(set(zip(r.get('intuneDevice.compliancePolicies[].name') or [], r.get('intuneDevice.compliancePolicies[].policyState') or [])))
    return '; '.join(f'{D(k)}: {POLICY_STATE.get(s) or D(s)}' for k, s in pairs) if pairs else 'None reported'


def failed_cell(r):
    """The settings that failed on the device, with Intune's setting names beneath."""
    xs = failed[r['id']]
    if not xs:
        return {'text': 'None reported'}
    return {'text': '; '.join(D(lab) + ('' if s == 'nonCompliant' else f' ({POLICY_STATE[s]})') for lab, _, s in xs),
            'sub': 'Intune: ' + ', '.join(D(nm) for _, nm, _ in xs)}


# ---------------------------------------------------------------- disk encryption and BitLocker recovery keys
def encryption(r):
    if not r.get('intuneDeviceId'):
        return 'No Intune record'
    if cloud_pc(r):
        return CLOUD_PC
    return g(r, 'intuneDevice.encryptionStatus.encryptionState') or 'No encryption report'


def enc_cell(r):
    """Encryption for a device table: a Cloud PC shows CLOUD_PC with Intune's own value beneath."""
    if r.get('intuneDeviceId') and cloud_pc(r):
        raw = g(r, 'intuneDevice.encryptionStatus.encryptionState')
        return R.state(CLOUD_PC, raw, 'Intune') if raw else {'text': CLOUD_PC}
    return intune(r, 'intuneDevice.encryptionStatus.encryptionState', ENCRYPTION, 'No encryption report')


def bitlocker(r):
    raw = g(r, 'intuneDevice.encryptionStatus.advancedBitLockerStates')
    if raw is None:
        return {'text': 'Not reported'}
    return R.state('; '.join(BITLOCKER.get(x.strip(), x.strip()) for x in raw.split(',')), raw, 'Intune')


def key_state(r):
    return KEY.get(g(r, 'isBitlockerRecoveryKeyEscrowed'), 'Not reported')


enc = fact('encryption.state', tally(A, encryption, list(ENCRYPTION), list(ENCRYPTION)), 'corporate_active')
CPC = [r for r in A if r.get('intuneDeviceId') and cloud_pc(r)]
fact('encryption.cloudPcs', [r['displayName'] for r in CPC], 'corporate_active')
cpc_reported = fact('encryption.cloudPcsReportedNotEncrypted', sum(1 for r in CPC if g(r, 'intuneDevice.encryptionStatus.encryptionState') == 'notEncrypted'),
                    'corporate_active')
W = [r for r in A if r.get('operatingSystem') == 'Windows']
windows = fact('windows.devices', len(W), 'corporate_active')
ENC_ROWS = list(ENCRYPTION) + [CLOUD_PC, 'No encryption report', 'No Intune record']
KEY_COLS = list(KEY.values()) + ['Not reported']
key_by_state = {s: Counter(key_state(r) for r in W if encryption(r) == s) for s in ENC_ROWS}
key_by_state = fact('encryption.windowsKeyByState', {s: {'devices': sum(c.values()), **{k: c[k] for k in KEY_COLS}}
                                                     for s, c in key_by_state.items() if sum(c.values()) or s in ENCRYPTION},
                    'corporate_active')
unencrypted = sorted((r for r in A if encryption(r) == 'notEncrypted'), key=name_key)
fact('encryption.notEncrypted', [r['displayName'] for r in unencrypted], 'corporate_active')

# ---------------------------------------------------------------- firewall
def firewall(r):
    if not r.get('intuneDeviceId'):
        return 'No Intune record'
    label = g(r, 'intuneDevice.firewallStatus.firewallStatus_loc')
    code = g(r, 'intuneDevice.firewallStatus.firewallStatus')
    if label is None and code is not None and code.isdigit() and int(code) < len(FIREWALL):
        label = FIREWALL[int(code)]
    return label or 'No firewall report'


fw = fact('firewall.status', tally(W, firewall, FIREWALL, FIREWALL), 'corporate_active')
fw_other = sorted((r for r in W if firewall(r) not in QUIET and firewall(r) != 'Enabled'),
                  key=lambda r: (not high(r), order_of(FIREWALL, firewall(r)), r['displayName'].lower(), r['id']))
fact('firewall.notEnabled', [r['displayName'] for r in fw_other], 'corporate_active')

# ---------------------------------------------------------------- inventory of active corporate devices
INV = sorted(A, key=name_key)
mb_per_gb = fact('inventory.mbPerGb', MB_PER_GB, 'recipe rule: Intune reports storage in MB')
fact('inventory.devices', {r['displayName'] + ' | ' + r['id']: {
    'serial': g(r, 'intuneDevice.serialNumber'), 'model': model(r), 'manufacturer': maker(r), 'edition': g(r, 'operatingSystemEdition'),
    'tpm': g(r, 'intuneDevice.encryptionStatus.tpmSpecificationVersion'), 'storageGb': gb(r.get('intuneDevice.storageTotal')),
    'freeGb': gb(r.get('intuneDevice.storageFree')), 'enrollmentProfile': g(r, 'entraDevice.enrollmentProfileName')} for r in INV},
    'corporate_active')
inv_serial = fact('inventory.withSerial', sum(1 for r in INV if g(r, 'intuneDevice.serialNumber')), 'corporate_active')

# ---------------------------------------------------------------- Windows edition and Windows 11 readiness
editions = fact('windows.edition', tally(W, lambda r: g(r, 'operatingSystemEdition') or ('Not reported' if r.get('intuneDeviceId')
                                                                                         else 'No Intune record')), 'corporate_active')
eligibility = fact('windows.upgradeEligibility', tally(W, lambda r: g(r, WFA + 'upgradeEligibility') or 'No Work From Anywhere record',
                                                       list(ELIGIBILITY), list(ELIGIBILITY)), 'corporate_active')
builds = fact('windows.build', tally(W, build_of), 'corporate_active')
not_capable = sorted((r for r in W if g(r, WFA + 'upgradeEligibility') == 'notCapable'), key=name_key)
fact('windows.notCapable', {r['displayName']: [label for f, label in CHECKS if r.get(WFA + f) is True] for r in not_capable}, 'corporate_active')

# ---------------------------------------------------------------- Intune check-in, by join type
CHECKIN = ['Fewer than 30 days', '30 days or more', 'No check-in recorded', 'No Intune record']


def checkin(r):
    if not r.get('intuneDeviceId'):
        return CHECKIN[3]
    a = R.age(R.when(r.get('intuneDeviceLastContact')))
    return CHECKIN[2] if a is None else CHECKIN[0] if a < 30 else CHECKIN[1]


checkins = fact('intune.checkIn', {b: sum(1 for r in A if checkin(r) == b) for b in CHECKIN}, 'corporate_active')
join_rows = [j for j in JOIN if j in by_join or j == 'Entra hybrid joined'] + [j for j in by_join if j not in JOIN]
checkin_by_join = fact('intune.checkInByJoinType', {j: {'devices': sum(1 for r in A if (g(r, 'joinType') or 'Not reported') == j),
                                                        **{b: sum(1 for r in A if (g(r, 'joinType') or 'Not reported') == j and checkin(r) == b)
                                                           for b in CHECKIN}} for j in join_rows}, 'corporate_active')
quiet_intune = sorted((r for r in A if checkin(r) in CHECKIN[1:3]), key=name_key)
fact('intune.noCheckInWithin30Days', [r['displayName'] for r in quiet_intune], 'corporate_active')

# ---------------------------------------------------------------- Windows Autopilot
AP = sorted(R.rows('autopilot_registered'), key=lambda r: (r['displayName'].lower(), r['id']))
registered = fact('autopilot.registered', len(AP), 'autopilot_registered')
AP_BUCKETS = ['Within 30 days of collection', 'More than 30 days before collection', 'Never contacted']


def autopilot_bucket(r):
    a = R.age(R.when(r.get('autopilotDeviceLastContact')))
    return AP_BUCKETS[2] if a is None else AP_BUCKETS[0] if a <= 30 else AP_BUCKETS[1]


def standing(r):
    """The device record's ownership classification and, for corporate devices, activity."""
    o = g(r, 'ownershipClassification') or 'Not reported'
    return f'{o}, {"inactive" if r.get("isInactive") else "active"}' if o == 'Corporate' else o


ap_contact = fact('autopilot.lastContact', {b: sum(1 for r in AP if autopilot_bucket(r) == b) for b in AP_BUCKETS}, 'autopilot_registered')
ap_state = fact('autopilot.enrollmentState', tally(AP, lambda r: g(r, 'autopilotEnrollmentState') or 'Not reported', list(AUTOPILOT)),
                'autopilot_registered')
ap_standing = fact('autopilot.byStanding', tally(AP, standing, ['Corporate, active', 'Corporate, inactive', 'Personal', 'Unknown']),
                   'autopilot_registered')
ap_stale = sorted((r for r in AP if autopilot_bucket(r) != AP_BUCKETS[0]),
                  key=lambda r: (not high(r), r.get('autopilotDeviceLastContact') or '', r['displayName'].lower(), r['id']))
fact('autopilot.notContactedWithin30Days', [r['displayName'] for r in ap_stale], 'autopilot_registered')

# ---------------------------------------------------------------- Secure Score controls: leave out Defender's Application category
controls = R.IN['secure_score_controls']['results']
app = sorted((c for c in controls if c.get('securityCenterRecommendation.recommendationCategory') == 'Application'), key=lambda c: c['id'])
fact('secureScore.controls.applicationLeftOut', {c['id']: c['title'] for c in app}, 'secure_score_controls')
R.IN['secure_score_controls']['results'] = [c for c in controls if c.get('securityCenterRecommendation.recommendationCategory') != 'Application']
snap = R.IN['secure_score'].get('snapshot') or {}  # a tenant can have no snapshot yet
extra = ([('Defender exposure score', snap['defenderExposureScore'], snap.get('maxDefenderExposureScore') or 100,
           'Microsoft Defender Vulnerability Management; lower is lower exposure')] if snap.get('defenderExposureScore') is not None else [])

# ================================================================ sections
tenant, as_of = R.tenant_raw, R.as_of
R.hero(f'Device records, coverage across Entra, Intune and Defender, high-impact devices, Defender exposure and antivirus, '
       f'Intune compliance, disk encryption, firewall, {WIN11} readiness and Windows Autopilot in the {tenant} Microsoft 365 '
       f'tenant, from data collected on {as_of}.',
       scope=[('Device records', n(records), 'Entra, Intune, Defender and Autopilot records, merged'),
              ('Corporate', n(corporate), 'Marked corporate in Intune or Entra, or Entra joined'),
              ('Active corporate', n(active), 'Contact from any source within 30 days')])
R.kpis([
    {'kicker': 'Missing from Intune or Defender', 'value': n(gap_any), 'unit': f' of {n(active)}',
     'foot': f'Not enrolled in Intune: {n(missing["Not enrolled in Intune"])}. Not onboarded to Defender: '
             f'{n(missing["Not onboarded to Defender"])}. In neither: {n(missing["In neither Intune nor Defender"])}.'},
    {'kicker': 'High-impact devices', 'value': n(len(HI)), 'unit': f' of {n(active)}',
     'foot': f'Onboarded to Defender: {n(hi_onboarded)}. Exposure level High: {n(hi_exposed)}. '
             f'With software that has a Critical CVE: {n(hi_critical)}.'},
    {'kicker': 'Defender exposure level High', 'value': n(exposure['High']), 'unit': f' of {n(onboarded)}',
     'foot': '. '.join(['Onboarded active corporate devices'] + [f'{k}: {n(v)}' for k, v in exposure.items() if k != 'High' and v]) + '.'
             if onboarded else ABSENT['Defender']},
    {'kicker': 'Encrypted in Intune’s encryption report', 'value': n(enc['encrypted']), 'unit': f' of {n(active)}',
     'foot': '. '.join(f'{ENCRYPTION.get(k, k)}: {n(v)}' for k, v in enc.items() if k != 'encrypted' and v) + '.'
             if any(v for k, v in enc.items() if k != 'encrypted') else 'Every active corporate device reports Encrypted.'},
])
R.findings('device_findings_open', 'device_findings_accepted', ['Device'], 'Device findings')
R.secure_score('secure_score', 'secure_score_controls', 'device',
               f'Recommended actions in Microsoft’s Device category below their maximum points, except {n(len(app))} in Defender’s Application '
               f'recommendation category', extra=extra)

# ---------------------------------------------------------------- records and the working set
section('Device records', 'Ownership and activity', [
    {'kicker': f'Device records by ownership: {n(records)}', 'bars': bars(by_owner, records),
     'note': 'Ownership is the collected classification: an Intune or Entra ownership marking first, then the Entra join type.'},
    {'kicker': f'Corporate devices by activity: {n(corporate)}', 'bars': bars(by_activity, corporate, data=False),
     'note': 'Inactive: the latest contact from Entra, Intune, Defender or Autopilot is more than 30 days before collection.'},
    {'kicker': f'Inactive corporate devices by days since last contact: {n(len(I))}', 'bars': bars(inactive_age, len(I), data=False),
     'note': f'Days from the latest contact on any source to {as_of}.'},
    {'kicker': 'Inactive corporate devices by sources holding a record', 'bars': bars(inactive_src, len(I), data=False)}],
    'device-records', cols=2, sub=checks('stale'))

model_rows = [{'maker': {'text': D(k) if k else 'Not reported'}, 'model': {'text': D(m) if m else 'Not reported'}, 'devices': n(c)}
              for (k, m), c in shown]
if rest:
    model_rows.append({'maker': {'text': ''}, 'model': {'text': f'Other models: {n(len(rest))}'}, 'devices': n(sum(c for _, c in rest))})
section('Active corporate devices', f'Operating system, join type and model: {n(active)} devices', [
    {'kicker': 'Operating system', 'bars': bars(by_os, active), 'note': 'As Entra reports it, or Intune, or Defender when the others have none.'},
    {'kicker': 'Join type', 'bars': bars(by_join, active),
     'note': 'From the Entra trust type: AzureAd is Entra joined, ServerAd is Entra hybrid joined, Workplace is Entra registered.'},
    {'kicker': 'Entra profile type', 'bars': bars(by_profile, active, PROFILE),
     'note': ' '.join(x for x in ('Microsoft’s deviceProfileType on the Entra device.', values('Entra', by_profile, PROFILE)) if x)},
    {'kicker': f'Models: {n(len(models))}', 'cols': [{'key': 'maker', 'label': 'Manufacturer'}, {'key': 'model', 'label': 'Model'},
                                                     {'key': 'devices', 'label': 'Devices', 'n': True}],
     'rows': model_rows,
     'note': f'The {n(len(shown))} models with the most devices. Model and manufacturer as Entra reports them, or Intune when Entra has none.'}],
    'active-devices', cols=2)

# ---------------------------------------------------------------- coverage
gap_cols = ([{'key': 'device', 'label': 'Device'}, {'key': 'os', 'label': 'Operating system'}, {'key': 'model', 'label': 'Model'}]
            + [{'key': key, 'label': label} for s, key, label in (('Entra', 'entra', 'Entra sign-in'), ('Intune', 'intune', 'Intune check-in'),
                                                                    ('Defender', 'defender', 'Defender report')) if s not in absent])
gap_rows = [{'device': device(r), 'os': system(r), 'model': hardware(model(r), maker(r)), 'entra': entra_seen(r),
             'intune': intune_seen(r), 'defender': defender_seen(r)} for r in gaps]
watched_names = [s for s, _ in watched]
gap_scope = ', '.join(watched_names[:-1]) + (' or ' if len(watched_names) > 1 else '') + watched_names[-1] if watched_names else ''
coverage_panels = [
    {'kicker': f'Missing from each source, of {n(active)} active corporate devices', 'bars': bars(missing, active, data=False),
     'note': 'A device missing from more than one source counts in each row. Defender: an onboarded Defender for Endpoint record.'},
    {'kicker': 'Sources that see the device', 'bars': bars(by_combo, active, data=False),
     'note': 'Each device once, by the sources holding a linked record for it.'}]
if gap_scope:
    coverage_panels.append(table(
        f'Missing from at least one source: {n(len(gaps))}' if len(watched) == len(SOURCES) else f'Missing from {gap_scope}: {n(len(gaps))}',
        gap_cols, gap_rows,
        'High-impact devices first, then by the sources that see the device and by name. Dates are the latest Entra sign-in, '
        'Intune check-in and full Defender report.',
        f'Every active corporate device has a record in {gap_scope}.'))
section('Three-way coverage', 'What Entra, Intune and Defender miss among active corporate devices', coverage_panels, 'coverage',
        sub=' '.join(x for x in [ABSENT[s] for s in absent] + [checks('notIntune', 'notDefender')] if x))

# ---------------------------------------------------------------- high impact
section('High impact', f'High-impact active corporate devices: {n(len(HI))}', [table(
    'Exposure, risk, sensor health, Critical CVEs, encryption and compliance',
    [{'key': 'device', 'label': 'Device'}, {'key': 'exp', 'label': 'Exposure level'}, {'key': 'risk', 'label': 'Risk score'},
     {'key': 'sensor', 'label': 'Sensor health'}, {'key': 'crit', 'label': 'Software with a Critical CVE', 'n': True},
     {'key': 'enc', 'label': 'Encryption'}, {'key': 'comp', 'label': 'Compliance'}],
    [{'device': device(r, mark=False), 'exp': defender(r, 'defenderDevice.exposureLevel'), 'risk': defender(r, 'defenderDevice.riskScore'),
      'sensor': defender(r, 'defenderDevice.healthStatus', SENSOR), 'crit': critical_cell(r),
      'enc': enc_cell(r),
      'comp': intune(r, 'intuneCompliantState', COMPLIANCE)} for r in HI],
    'By exposure level, software with a Critical CVE, risk score and name. Software with a Critical CVE: software records Defender '
    'Vulnerability Management lists on the device whose highest-rated CVE is Critical, matched on the software version. Software '
    'that Defender identifies by a CPE name is not matched to CVEs in the collected data.'
    + (' Not counted: the query returns the devices with the most such records, up to its limit, and this device is not among them.'
       if crit_cut else ''),
    'No active corporate device is marked high impact in the collected data.')],
    'high-impact',
    sub='High impact: the device’s primary user holds a privileged directory role or is in the configured org chart, or a technician '
        'marked the user or the device.')

# ---------------------------------------------------------------- Defender
if onboarded:
    defender_panels = [
        {'kicker': f'Exposure level, of {n(onboarded)} onboarded', 'bars': bars(exposure, onboarded),
         'note': 'Defender’s rating of unpatched vulnerabilities and insecure configuration on the device.'},
        {'kicker': f'Risk score, of {n(onboarded)} onboarded', 'bars': bars(risk, onboarded),
         'note': 'Defender’s rating driven by active alerts on the device. None: no elevated risk.'}]
else:
    defender_panels = [{'kicker': 'Exposure level and risk score', 'note': ABSENT['Defender']}]
section('Microsoft Defender', f'Exposure level and risk score: {n(onboarded)} onboarded devices', defender_panels, 'defender', cols=2,
        sub=checks('exposure', 'risk'))
section('Microsoft Defender', f'Exposure level High, or risk score High or Medium: {n(len(exposed))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'os', 'label': 'Operating system'}, {'key': 'model', 'label': 'Model'},
           {'key': 'exp', 'label': 'Exposure level'}, {'key': 'risk', 'label': 'Risk score'},
           {'key': 'sensor', 'label': 'Sensor health'}, {'key': 'seen', 'label': 'Defender report'}],
    [{'device': device(r), 'os': system(r), 'model': hardware(model(r), maker(r)), 'exp': defender(r, 'defenderDevice.exposureLevel'),
      'risk': defender(r, 'defenderDevice.riskScore'), 'sensor': defender(r, 'defenderDevice.healthStatus', SENSOR),
      'seen': defender_seen(r)} for r in exposed],
    'Onboarded active corporate devices with exposure level High or risk score High or Medium. High-impact devices first, then by '
    'exposure, risk and name.',
    'No onboarded active corporate device has exposure level High or risk score High or Medium.' if onboarded else ABSENT['Defender'])],
    'defender-devices')

if onboarded:
    component_rows = [{'part': {'text': name}, **{k.lower(): n(components[name].get(k, 0)) for k in CURRENT},
                       'none': n(components[name].get('Not reported', 0))} for name, _ in COMPONENTS]
    antivirus_panels = [
        {'kicker': 'Sensor health', 'bars': bars(sensor, onboarded, SENSOR),
         'note': ' '.join(x for x in ('The Defender sensor’s own reporting state.', values('Defender', sensor, SENSOR)) if x)},
        {'kicker': 'Defender Antivirus mode', 'bars': bars(av_mode, onboarded, AV_MODE),
         'note': ' '.join(x for x in ('Active: Defender Antivirus is the primary antivirus. Passive: another antivirus is primary.',
                                     values('Defender', av_mode, AV_MODE)) if x)},
        {'kicker': 'Antivirus components',
         'cols': [{'key': 'part', 'label': 'Component'}] + [{'key': k.lower(), 'label': label, 'n': True} for k, label in CURRENT.items()]
                 + [{'key': 'none', 'label': 'Not reported', 'n': True}],
         'rows': component_rows,
         'note': 'Defender values: True (Up to date), False (Out of date), Unknown (No data available). No data available: the device has '
                 'not reported to the antivirus health report in more than 7 days.'},
        {'kicker': 'Devices by antivirus components up to date', 'bars': bars(av_devices, onboarded, data=False),
         'note': 'Signature, engine and platform together. A device with one out of date counts there even if another has no data.'}]
else:
    antivirus_panels = [{'kicker': 'Sensor health and antivirus', 'note': ABSENT['Defender']}]
section('Antivirus', f'Defender sensor and antivirus health: {n(onboarded)} onboarded devices', antivirus_panels, 'antivirus', cols=2,
        sub=checks('sensor', 'avMode', 'avCurrent'))
section('Antivirus', f'Sensor or antivirus not Active, or a component not up to date: {n(len(av_flag))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'sensor', 'label': 'Sensor health'}, {'key': 'mode', 'label': 'Antivirus mode'},
           {'key': 'sig', 'label': 'Signature'}, {'key': 'eng', 'label': 'Engine'}, {'key': 'plat', 'label': 'Platform'},
           {'key': 'seen', 'label': 'Defender report'}],
    [{'device': device(r), 'sensor': defender(r, 'defenderDevice.healthStatus', SENSOR),
      'mode': defender(r, 'defenderDevice.deviceAvInfo.avModeName', AV_MODE), 'sig': defender(r, COMPONENTS[0][1], CURRENT),
      'eng': defender(r, COMPONENTS[1][1], CURRENT), 'plat': defender(r, COMPONENTS[2][1], CURRENT), 'seen': defender_seen(r)} for r in av_flag],
    'Onboarded active corporate devices whose sensor health or antivirus mode is not Active, or with a component not Up to date. '
    'High-impact devices first, then by sensor health and name.',
    'Every onboarded active corporate device reports sensor health Active, antivirus mode Active and every component Up to date.'
    if onboarded else ABSENT['Defender'])],
    'antivirus-devices')

# ---------------------------------------------------------------- Intune compliance
section('Intune compliance', f'Compliance state and policies: {n(active)} active corporate devices', [
    {'kicker': 'Compliance state', 'bars': bars(compliance, active, COMPLIANCE),
     'note': ' '.join(x for x in ('Intune’s compliance state for the device, as the Intune Devices report gives it.',
                                 values('Intune', compliance, COMPLIANCE)) if x)},
    {'kicker': f'Compliance policies: {n(len(policy_rows))}',
     'cols': [{'key': 'policy', 'label': 'Policy'}, {'key': 'devices', 'label': 'Devices', 'n': True}]
             + [{'key': s, 'label': POLICY_STATE.get(s) or D(s), 'n': True} for s in policy_states],
     'rows': [{'policy': {'text': D(k)}, 'devices': n(v['devices']), **{s: n(v['states'].get(s, 0)) for s in policy_states}} for k, v in policy_rows],
     'note': ' '.join(x for x in ('Each policy’s state on each device as Intune reports it. Policies in state unknown or notApplicable are not '
                                 'collected. A device’s compliance state and its policy states come from separate Intune reports, so '
                                 'they can disagree.', values('Intune', policy_states, POLICY_STATE)) if x)},
    {'kicker': f'Settings that failed: {n(len(setting_rows))}',
     'cols': [{'key': 'setting', 'label': 'Setting'}, {'key': 'devices', 'label': 'Devices', 'n': True}],
     'rows': [{'setting': {'text': D(lab), 'sub': f'Intune: {D(nm)}'}, 'devices': n(c)} for (lab, nm), c in setting_rows],
     'note': 'Compliance settings Intune reports as nonCompliant, error or conflict, by the devices they failed on. Intune’s per-setting '
             'results are collected for devices it rates not compliant and for policies in a failing state.'}
    if setting_rows else {'kicker': 'Settings that failed: 0', 'note': 'No compliance setting on an active corporate device is reported as '
                          'nonCompliant, error or conflict.' if enrolled else ABSENT['Intune']}],
    'compliance', cols=2, sub=checks('noncompliant'))
section('Intune compliance', f'Devices with a state other than Compliant: {n(len(not_compliant))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'state', 'label': 'Compliance state'},
           {'key': 'grace', 'label': 'Grace period end'}, {'key': 'policies', 'label': 'Policy states'},
           {'key': 'failed', 'label': 'Settings that failed'}, {'key': 'sync', 'label': 'Intune check-in'}],
    [{'device': device(r), 'state': intune(r, 'intuneCompliantState', COMPLIANCE),
      'grace': R.day(R.when(r.get('intuneInGracePeriodUntil')), none='No grace period'),
      'policies': {'text': policy_text(r)}, 'failed': failed_cell(r), 'sync': intune_seen(r)} for r in not_compliant],
    'Active corporate devices with an Intune record and a compliance state other than Compliant. High-impact devices first, then by '
    'state and name. Settings that failed: the compliance settings Intune reports as nonCompliant, error or conflict on the device, '
    'with Intune’s setting names beneath; a state other than nonCompliant follows the setting in brackets.',
    'Every active corporate device with an Intune record reports Compliant.' if enrolled else ABSENT['Intune'])],
    'compliance-devices')

# ---------------------------------------------------------------- disk encryption and recovery keys
key_rows = [{'state': st(ENCRYPTION, s, 'Intune', s) if s in ENCRYPTION else {'text': s}, 'devices': n(c['devices']),
             **{f'k{i}': n(c[k]) for i, k in enumerate(KEY_COLS)}} for s, c in key_by_state.items()]
section('Disk encryption', f'Encryption state and BitLocker recovery keys: {n(active)} active corporate devices', [
    {'kicker': 'Encryption state', 'bars': bars(enc, active, ENCRYPTION),
     'note': ' '.join(x for x in ('From Intune’s device encryption report: BitLocker on Windows, FileVault on macOS.',
                                 values('Intune', enc, ENCRYPTION),
                                 f'{CLOUD_PC}: a Windows 365 Cloud PC, found by Microsoft’s rule for a filter of all Cloud PCs (the '
                                 'Intune model contains Cloud PC or Windows 365). Windows 365 encrypts Cloud PC disks with Azure Storage '
                                 'server-side encryption and host-based encryption, and doesn’t support BitLocker on them; Intune reports '
                                 f'{n(cpc_reported)} of these Cloud PCs as Not encrypted.' if CPC else '') if x)},
    {'kicker': f'BitLocker recovery key by encryption state, {n(windows)} Windows devices',
     'cols': [{'key': 'state', 'label': 'Encryption state'}, {'key': 'devices', 'label': 'Devices', 'n': True}]
             + [{'key': f'k{i}', 'label': k, 'n': True} for i, k in enumerate(KEY_COLS)],
     'rows': key_rows,
     'note': 'Key held in Entra ID: Entra ID holds a recovery key for the operating-system volume. Keys kept only in on-premises Active '
             'Directory are not visible.'}],
    'encryption', cols=2, sub=checks('encryption', 'recoveryKey'))
section('Disk encryption', f'Devices reported Not encrypted: {n(len(unencrypted))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'model', 'label': 'Model'}, {'key': 'profile', 'label': 'Entra profile type'},
           {'key': 'ready', 'label': 'Encryption readiness'}, {'key': 'state', 'label': 'BitLocker state'},
           {'key': 'key', 'label': 'Recovery key in Entra ID'}],
    [{'device': device(r), 'model': hardware(model(r), maker(r)), 'profile': st(PROFILE, g(r, 'entraDevice.profileType'), 'Entra', 'Not reported'),
      'ready': intune(r, 'intuneDevice.encryptionStatus.encryptionReadinessState', READINESS), 'state': bitlocker(r),
      'key': {'True': 'Yes', 'False': 'No'}.get(g(r, 'isBitlockerRecoveryKeyEscrowed'), 'Not reported')} for r in unencrypted],
    'Every active corporate device whose encryption state is Not encrypted. High-impact devices first, then by name. BitLocker state is '
    'Intune’s detailed BitLocker status.' + (f' Cloud PCs are counted under {CLOUD_PC}, not here: {n(len(CPC))}.' if CPC else ''),
    'No active corporate device reports Not encrypted.' if enrolled else ABSENT['Intune'])],
    'encryption-devices')

# ---------------------------------------------------------------- firewall
section('Firewall', f'Firewall status: {n(windows)} Windows devices', [
    {'kicker': 'Firewall status', 'bars': bars(fw, windows),
     'note': 'Intune’s firewall report (MDM Firewall status for Windows), which covers Windows devices. Temporarily Disabled (default): '
             'the firewall is temporarily not monitoring all networks. Not applicable: the device doesn’t support firewall reporting.'},
    table('Windows devices with a status other than Enabled: ' + n(len(fw_other)),
          [{'key': 'device', 'label': 'Device'}, {'key': 'status', 'label': 'Firewall status'},
           {'key': 'reported', 'label': 'Firewall report'}, {'key': 'sync', 'label': 'Intune check-in'}],
          [{'device': device(r), 'status': {'text': D(firewall(r))},
            'reported': R.day(R.when(r.get('intuneDevice.firewallStatus.lastReportedDateTime')), none='No report date'),
            'sync': intune_seen(r)} for r in fw_other],
          'High-impact devices first, then by status and name.',
          'No Windows device reports a firewall status other than Enabled.')],
    'firewall', cols=2, sub=checks('firewall'))

# ---------------------------------------------------------------- Windows edition and Windows 11 readiness
section(f'{WIN11} readiness', f'Edition, upgrade eligibility and build: {n(windows)} Windows devices', [
    {'kicker': 'Windows edition', 'bars': bars(editions, windows), 'note': 'Intune’s SKU family for the device.'},
    {'kicker': 'Upgrade eligibility', 'bars': bars(eligibility, windows, ELIGIBILITY),
     'note': ' '.join(x for x in (f'Endpoint Analytics eligibility for {WIN11}, from the Work From Anywhere report on Intune-managed devices.',
                                 values('Endpoint Analytics', eligibility, ELIGIBILITY)) if x)},
    {'kicker': 'Windows build', 'bars': bars(builds, windows), 'note': 'The first three parts of the operating system version.'}],
    'windows', cols=2, sub=checks('home', 'win11'))
section(f'{WIN11} readiness', f'Devices reported Not capable: {n(len(not_capable))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'model', 'label': 'Model'}, {'key': 'build', 'label': 'Build'},
           {'key': 'checks', 'label': 'Failed checks'}, {'key': 'sync', 'label': 'Intune check-in'}],
    [{'device': device(r), 'model': hardware(model(r), maker(r)), 'build': {'text': build_of(r)},
      'checks': {'text': ', '.join(label for f, label in CHECKS if r.get(WFA + f) is True) or 'None reported'},
      'sync': intune_seen(r)} for r in not_capable],
    'Every Windows device whose eligibility is Not capable, with the hardware and software checks it fails. High-impact devices first, '
    'then by name.',
    'No Windows device reports Not capable.')],
    'windows-devices')

# ---------------------------------------------------------------- Intune check-in
section('Intune check-in', f'Days since the latest Intune check-in: {n(active)} active corporate devices', [
    {'kicker': f'Latest Intune check-in, of {n(active)} active corporate devices', 'bars': bars(checkins, active, data=False),
     'note': f'Days from Intune’s last check-in (Graph lastSyncDateTime) to {as_of}.'},
    {'kicker': 'By join type',
     'cols': [{'key': 'join', 'label': 'Join type'}, {'key': 'devices', 'label': 'Devices', 'n': True}]
             + [{'key': f'c{i}', 'label': b, 'n': True} for i, b in enumerate(CHECKIN)],
     'rows': [{'join': {'text': D(j) if j != 'Not reported' else j}, 'devices': n(c['devices']),
               **{f'c{i}': n(c[b]) for i, b in enumerate(CHECKIN)}} for j, c in checkin_by_join.items()],
     'note': 'Entra hybrid joined: joined to on-premises Active Directory and registered in Entra ID.'},
    table('Intune record with no check-in in the last 30 days: ' + n(len(quiet_intune)),
          [{'key': 'device', 'label': 'Device'}, {'key': 'join', 'label': 'Join type'}, {'key': 'sync', 'label': 'Intune check-in'},
           {'key': 'entra', 'label': 'Entra sign-in'}, {'key': 'defender', 'label': 'Defender report'}],
          [{'device': device(r), 'join': {'text': D(g(r, 'joinType')) if g(r, 'joinType') else 'Not reported'}, 'sync': intune_seen(r),
            'entra': entra_seen(r), 'defender': defender_seen(r)} for r in quiet_intune],
          'High-impact devices first, then by name.',
          'Every active corporate device with an Intune record checked in to Intune fewer than 30 days before collection.'
          if enrolled else ABSENT['Intune'])],
    'intune-checkin', cols=2, sub=checks('hybridIntune'))

# ---------------------------------------------------------------- Windows Autopilot
if registered:
    autopilot_panels = [
        {'kicker': f'Last contact with the Autopilot service, of {n(registered)} registered', 'bars': bars(ap_contact, registered, data=False),
         'note': f'Days from the registration’s last contact (Graph lastContactedDateTime) to {as_of}. Never contacted: the hardware is '
                 'registered but has not enrolled.'},
        {'kicker': 'Enrollment state', 'bars': bars(ap_state, registered, AUTOPILOT),
         'note': values('Autopilot', ap_state, AUTOPILOT) or 'As the Autopilot registration reports it.'},
        {'kicker': 'Device record: ownership and activity', 'bars': bars(ap_standing, registered, data=False),
         'note': 'The classification and activity of the device record the registration is linked to.'}]
else:
    autopilot_panels = [{'kicker': 'Autopilot-registered devices: 0', 'note': 'No device record in the collected data is linked to a '
                         'Windows Autopilot registration.'}]
section('Windows Autopilot', f'Autopilot-registered devices: {n(registered)}', autopilot_panels, 'autopilot', cols=2,
        sub=' '.join(x for x in ('Registrations the collector cannot read (no Intune license, or DeviceManagementServiceConfig.Read.All not '
                                 'granted) count as not registered.', checks('autopilot')) if x))
section('Windows Autopilot', f'No contact with the Autopilot service within 30 days: {n(len(ap_stale))}', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'model', 'label': 'Autopilot model'}, {'key': 'state', 'label': 'Enrollment state'},
           {'key': 'contact', 'label': 'Last Autopilot contact'}, {'key': 'standing', 'label': 'Device record'},
           {'key': 'sources', 'label': 'Other records'}],
    [{'device': device(r), 'model': hardware(g(r, 'autopilotDevice.model'), g(r, 'autopilotDevice.manufacturer')),
      'state': st(AUTOPILOT, g(r, 'autopilotEnrollmentState'), 'Autopilot', 'Not reported'),
      'contact': R.day(R.when(r.get('autopilotDeviceLastContact')), none='Never contacted'), 'standing': {'text': standing(r)},
      'sources': {'text': ', '.join(combo(r)) or 'None'}} for r in ap_stale],
    'Autopilot-registered devices whose last contact is more than 30 days before collection, or that never contacted the service. '
    'High-impact devices first, then never contacted, then by last contact, oldest first, and by name. Other records: the Entra, '
    'Intune and Defender records linked to the device.',
    'Every Autopilot-registered device contacted the Autopilot service within 30 days.' if registered
    else 'There are no Autopilot-registered devices to list.')],
    'autopilot-devices')

# ---------------------------------------------------------------- inventory
def storage(r):
    """Total storage in GB with the free space beneath, as Intune reports them."""
    if not r.get('intuneDeviceId'):
        return {'text': 'No Intune record'}
    total, free = gb(r.get('intuneDevice.storageTotal')), gb(r.get('intuneDevice.storageFree'))
    if total is None:
        return {'text': 'Not reported'}
    return {'text': f'{n(total)} GB', 'sub': f'{n(free)} GB free' if free is not None else 'Free space not reported'}


section('Inventory', f'Device inventory: {n(active)} active corporate devices', [table(
    None, [{'key': 'device', 'label': 'Device'}, {'key': 'model', 'label': 'Model'}, {'key': 'serial', 'label': 'Serial number'},
           {'key': 'os', 'label': 'Operating system'}, {'key': 'tpm', 'label': 'TPM version'},
           {'key': 'storage', 'label': 'Storage'},
           {'key': 'profile', 'label': 'Enrollment profile'}],
    [{'device': device(r), 'model': hardware(model(r), maker(r)),
      'serial': {'mono': D(g(r, 'intuneDevice.serialNumber'))} if g(r, 'intuneDevice.serialNumber') else intune(r, 'intuneDevice.serialNumber'),
      'os': {**system(r), 'sub': D(g(r, 'operatingSystemEdition')) if g(r, 'operatingSystemEdition') else None},
      'tpm': intune(r, 'intuneDevice.encryptionStatus.tpmSpecificationVersion'),
      'storage': storage(r),
      'profile': {'text': D(g(r, 'entraDevice.enrollmentProfileName'))} if g(r, 'entraDevice.enrollmentProfileName') else {'text': 'Not reported'}}
     for r in INV],
    f'High-impact devices first, then by name. Serial number, storage and TPM version as Intune reports them, so a device with no Intune '
    f'record has none; {n(inv_serial)} devices have a serial number. Storage: total, with free space beneath; Intune reports MB, shown here in GB at {n(mb_per_gb)} MB '
    'to the GB. TPM version: the specification version in Intune’s encryption report, mainly for Windows. Enrollment profile: '
    'enrollmentProfileName on the Entra device record. Edition beneath the operating system.',
    'There are no active corporate devices to list.')],
    'inventory')

R.footer(f'Read-only collection on {as_of}. Values come from one collection run, through fixed queries of device records, finding '
         f'counts, Microsoft Secure Score and Defender software vulnerability records, the same queries for every tenant.',
         'Corporate: an Intune or Entra ownership marking of Corporate, or with no marking, an Entra joined device. Active: a contact '
         'from Entra, Intune, Defender or Autopilot within 30 days of collection. Seen by a source: a linked Entra device, Intune '
         'enrollment or onboarded Defender record. Primary user, under each device name: the first Entra registered owner, else the '
         'Intune primary user. High impact: the primary user holds a privileged directory role or is in the configured org chart, or '
         'a technician marked the user or the device.',
         'Personal and Unknown devices, and inactive corporate devices, outside Device records and Windows Autopilot. Defender records '
         'that are not onboarded, which the collected data does not link to a device. Secure Score recommended actions in Defender’s Application '
         'recommendation category.')
R.write()
