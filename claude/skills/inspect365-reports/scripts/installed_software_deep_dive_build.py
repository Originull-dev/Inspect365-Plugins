"""Installed software report recipe, v0.2.0. Facts only, built from saved query results with no model.

    python3 skills/inspect365-report-recipes/recipes/installed_software_deep_dive/build.py <run-dir>
    python3 skills/inspect365-report-recipes/render_report.py <run-dir> [--brand <profile.json>]
    python3 skills/inspect365-report-recipes/check_facts.py <run-dir>

Software comes from the Microsoft Defender Vulnerability Management software inventory (defender-applications)
and Intune discovered apps (intune-applications); CVEs from Defender's vulnerability records
(defender-application-vulnerabilities); the high-impact mark and Defender's exposure level from device records
(devices). A software version is one Defender inventory entry: one vendor, name and version on one OS platform
and architecture. Per version, the Critical, CVSS and exploit flags come from the entry's rollups, which cover
Defender's CVE records for that vendor, name and version on any platform. Tenant-wide CVE counts come from the
vulnerability records themselves. Every section works from one collection run. Tables that show part of a list
choose rows by the fixed rules in RULES and say so in their notes. Labels are Defender's and Microsoft's own.

0.2.0 (2026-10-07 review): working set in the title band; device counts from Defender machine ids, after a
saved response from 0.1.0 carried an extra end-of-support filter and showed 15 devices; installs, the platform,
device-overlap and vendor panels and the top-devices table removed; high-impact devices listed and marked; a data
view for every check; section ids.
"""
import pathlib, re, sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import IMPACT_REASON, Report, esc, n, width  # noqa: E402

R = Report(__file__, 'installed-software-deep-dive', '0.2.0', 'Installed software report')

# ---------------------------------------------------------------- rules and knowledge tables
# cvssAtLeast must match the cvssScore list in the cvss9_cves_by_id filter in queries.json.
RULES = R.fact('rules', {'cvssAtLeast': 9.0, 'topSoftware': 15, 'deviceNamesUpTo': 10}, 'recipe rules')
CVSS_MIN, TOP_SOFTWARE, NAMES_UP_TO = (RULES[k] for k in ('cvssAtLeast', 'topSoftware', 'deviceNamesUpTo'))
# Microsoft's names for Defender's OSPlatform values.
PLATFORM = {'Windows11': 'Windows 11', 'Windows11WVD': 'Windows 11 multi-session', 'Windows10': 'Windows 10',
            'Windows10WVD': 'Windows 10 multi-session', 'WindowsServer2016': 'Windows Server 2016',
            'WindowsServer2019': 'Windows Server 2019', 'WindowsServer2022': 'Windows Server 2022',
            'WindowsServer2025': 'Windows Server 2025', 'macOS': 'macOS', 'Linux': 'Linux', 'Android': 'Android',
            'iOS': 'iOS', '': 'No platform reported'}
# Defender's VulnerabilitySeverityLevel values, highest first; the portal shows the same words. '' is a CVE Defender
# has not rated yet; the entry rollup calls that Unknown when every matched CVE is unrated.
SEVERITY = ['Critical', 'High', 'Medium', 'Low', '']
SEV_LABEL = {'': 'Not yet rated', 'Unknown': 'Not yet rated'}
# Defender's EndOfSupportStatus values in table order, with the tags the Defender portal shows for them
# (Microsoft Learn, Plan for end-of-support software: "EOS software", "EOS versions", "Upcoming EOS versions").
EOS_ORDER = ['EOS Software', 'EOS Version', 'Upcoming EOS Software', 'Upcoming EOS Version']
EOS_LABEL = {'EOS Software': 'EOS software', 'EOS Version': 'EOS versions',
             'Upcoming EOS Software': 'Upcoming EOS software', 'Upcoming EOS Version': 'Upcoming EOS versions'}
# Defender's exposureLevel values, highest first, with the device inventory's labels (Microsoft Learn, Device
# inventory field reference: High, Medium, Low, No data available).
EXPOSURE_ORDER = ['High', 'Medium', 'Low', 'None']
EXPOSURE_LABEL = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'None': 'No data available'}
# Short labels for the installed software checks, used where the full check name does not fit (KPI foot).
CHECK_SHORT = {'48d9a5e1-bc5b-4a12-95a2-529ecbe92370': 'Critical vulnerabilities',
               'f76f3116-d214-481c-a14e-9be6567423b9': 'Available exploits',
               'eafa3015-8f9e-4624-9000-4fa51f9c6654': 'End of support',
               '1e3d28c6-f243-483f-b984-81e33079646d': 'Upcoming end of support'}
CHECK_CRITICAL, CHECK_EXPLOIT, CHECK_EOS, CHECK_UPCOMING = CHECK_SHORT
EXPOSURE_LEVELS = R.fact('exposureScore.levels', {'low': [0, 29], 'medium': [30, 69], 'high': [70, 100]},
                         'Microsoft Learn: Exposure score in Defender Vulnerability Management')
BAR = 'var(--series-1)'


def platform(p):
    return R.D(PLATFORM.get(p, p))


def sev(s):
    return R.D(SEV_LABEL.get(s, s))


def sev_rank(s):
    s = '' if s == 'Unknown' else s
    return SEVERITY.index(s) if s in SEVERITY else len(SEVERITY)


def label_cell(label, raw, source='Defender'):
    """Microsoft's label, with the source's raw value beneath when the two differ; an empty raw value shows as ""."""
    if label == raw:
        return {'text': R.D(label)}
    return R.state(label, raw if raw != '' else '""', source)


def sev_cell(s):
    return label_cell(sev(s), s)


def cvss(x):
    """CVSS as one-decimal text (Defender stores whole scores without a decimal)."""
    return f'{float(x):.1f}'


def us_date(s):
    """Defender's MM/dd/yyyy text date as an ISO date, or None."""
    m = re.match(r'(\d{1,2})/(\d{1,2})/(\d{4})', str(s or ''))
    return R.D(f'{int(m[3]):04d}-{int(m[1]):02d}-{int(m[2]):02d}') if m else None


def distinct(qid, skip_empty=False):
    """Distinct values of an aggregate's groupBy field: returned buckets plus the ones maxBuckets left out."""
    d = R.IN[qid]
    return d.get('bucketCount', 0) + d.get('omittedBucketCount', 0) - (1 if skip_empty and '' in R.buckets(qid) else 0)


def bars(counts, of):
    return [{'label': esc(R.D(k)), 'value': n(v), 'thin': True, 'pct': width(v, of), 'color': BAR} for k, v in counts]


def plural(x, word):
    return f'{n(x)} {word}' + ('' if x == 1 else 's')


# ---------------------------------------------------------------- findings (for the KPI) and inventories
f_open = R.buckets('software_findings_open')
defs = {d['id']: d for d in R.IN['definitions']['definitions'] if d['type'] == 'InstalledSoftware'}
checks = sorted(defs.values(), key=lambda d: (d['orderId'], d['displayName']))
check_name = {i: R.D(defs[i]['displayName']) if i in defs else R.D(CHECK_SHORT[i]) for i in CHECK_SHORT}
open_total = R.fact('kpi.openFindings', R.total('software_findings_open'), 'software_findings_open')
open_by_check = R.fact('kpi.openFindingsByCheck', {CHECK_SHORT.get(d['id'], d['displayName']): f_open.get(d['id'], 0) for d in checks},
                       'software_findings_open + definitions')

entries = R.fact('inventory.defender.entries', R.total('software_by_name'), 'software_by_name')
names = R.fact('inventory.defender.names', distinct('software_by_name'), 'software_by_name')
vendors = R.fact('inventory.defender.vendors', distinct('software_by_vendor', skip_empty=True), 'software_by_vendor')
# Devices in Defender's inventory: the Defender machine ids on its entries, which every entry carries. Machine ids
# with no device record have no name, primary user or high-impact mark; counted only when the record aggregate is whole.
d_devices = R.fact('inventory.defender.devices', distinct('software_by_device', skip_empty=True), 'software_by_device')
records = R.IN['software_device_records']
record_ids = {k for k in R.buckets('software_device_records') if k}
records_whole = records.get('omittedBucketCount', 0) == 0
d_unmatched = (R.fact('inventory.defender.machinesWithoutRecord', d_devices - len(record_ids), 'software_by_device + software_device_records')
               if records_whole else None)
ientries = R.fact('inventory.intune.entries', R.total('intune_by_name'), 'intune_by_name')
inames = R.fact('inventory.intune.names', distinct('intune_by_name'), 'intune_by_name')
publishers = R.fact('inventory.intune.publishers', distinct('intune_by_publisher', skip_empty=True), 'intune_by_publisher')
no_pub = R.fact('inventory.intune.noPublisher', R.buckets('intune_by_publisher').get('', 0), 'intune_by_publisher')
i_devices = R.fact('inventory.intune.devices', distinct('intune_by_device', skip_empty=True), 'intune_by_device')
i_unmatched = R.fact('inventory.intune.entriesWithoutRecord', R.buckets('intune_by_device').get('', 0), 'intune_by_device')

# ---------------------------------------------------------------- high-impact devices
# A device is high impact when its system.impactSources[] has an entry: 'inherited' from its primary user (sourceRule
# names the user's rule when the collector wrote it) or 'manualAssignment' by a technician.
HI = {d['id']: d for d in R.rows('high_impact_devices')}


def impact_reason(d):
    types = d.get('system.impactSources[].type') or []
    rules = sorted({x for x in (d.get('system.impactSources[].sourceRule') or []) if x})
    labels = [f"{IMPACT_REASON['inherited']} ({R.D(IMPACT_REASON.get(x, x))})" for x in rules if 'inherited' in types]
    if types.count('inherited') > len(labels):
        labels.append(IMPACT_REASON['inherited'])
    if 'manualAssignment' in types:
        labels.append(IMPACT_REASON['manualAssignment'])
    return R.D('; '.join(labels))


# ---------------------------------------------------------------- software versions with CVEs and their devices
V = sorted(R.rows('vulnerable_software'), key=lambda r: r['id'])
E = sorted(R.rows('eos_software'), key=lambda r: r['id'])
DEV = {}


def device_list(r):
    """(key, name) for each device on an entry; a Defender machine with no device record keys on its machine id."""
    ids, cores = r.get('devices[].defenderDeviceId') or [], r.get('devices[].coreDeviceId') or []
    names_ = r.get('devices[].displayName') or []
    out = []
    for i, machine in enumerate(ids):
        core = cores[i] if i < len(cores) else ''
        name = (names_[i] if i < len(names_) else '') or (HI[core]['displayName'] if core in HI else '')
        out.append((core or f'defender:{machine}', name or 'Not matched to a device record'))
    return out


def device(key):
    return DEV.setdefault(key, {'cve': 0, 'crit': 0, 'c9': 0, 'exp': 0, 'eos': 0, 'upcoming': 0})


for r in V:
    r['_crit'] = r.get('defenderApplication_maxSeverity') == 'Critical'
    r['_c9'] = float(r.get('defenderApplication_maxCvssScore') or 0) >= CVSS_MIN
    r['_exp'] = (r.get('defenderApplication_numExploits') or 0) > 0
    r['_any'] = r['_crit'] or r['_c9'] or r['_exp']
    r['_devs'] = sorted({k for k, _ in device_list(r)})
    for key in r['_devs']:
        d = device(key)
        d['cve'] += 1
        d['crit'] += r['_crit']
        d['c9'] += r['_c9']
        d['exp'] += r['_exp']
for r in E:
    r['_upcoming'] = str(r['endOfSupportStatus']).startswith('Upcoming')
    r['_devs'] = sorted({k for k, _ in device_list(r)})
    for key in r['_devs']:
        device(key)['upcoming' if r['_upcoming'] else 'eos'] += 1


def reach(rows):
    devs = {k for r in rows for k in r['_devs']}
    return {'versions': len(rows), 'devices': len(devs), 'highImpact': sum(1 for k in devs if k in HI)}


def hi_count(keys):
    return sum(1 for k in set(keys) if k in HI)


all_v, crit_v = reach(V), reach([r for r in V if r['_crit']])
c9_v, exp_v = reach([r for r in V if r['_c9']]), reach([r for r in V if r['_exp']])
eos_now = [r for r in E if not r['_upcoming']]
eos_v, eos_any, upcoming = reach(eos_now), reach(E), reach([r for r in E if r['_upcoming']])

# ---------------------------------------------------------------- data views for the four checks (every version)
sev_versions = R.fact('checks.versionsBySeverity', {
    **{SEV_LABEL.get(s, s): sum(1 for r in V if (r.get('defenderApplication_maxSeverity') or 'Unknown') == s)
       for s in ['Critical', 'High', 'Medium', 'Low', 'Unknown']},
    'No CVE record matched': entries - len(V)}, 'vulnerable_software + software_by_name')
exp_versions = R.fact('checks.versionsByExploit', {
    'With a CVE that has a public exploit': exp_v['versions'],
    'With CVEs, none with a public exploit': len(V) - exp_v['versions'],
    'No CVE record matched': entries - len(V)}, 'vulnerable_software + software_by_name')
eos_status = {s: sum(1 for r in E if r['endOfSupportStatus'] == s) for s in EOS_ORDER}
eos_status.update({s: sum(1 for r in E if r['endOfSupportStatus'] == s) for s in sorted({r['endOfSupportStatus'] for r in E} - set(EOS_ORDER))})
R.fact('eos.byStatus', eos_status, 'eos_software')
eos_versions = R.fact('checks.versionsByEndOfSupport', {**{EOS_LABEL.get(s, s): v for s, v in eos_status.items()},
                                                       'No end-of-support status': entries - len(E)},
                      'eos_software + software_by_name')
for s in eos_status:
    R.D(s)

# ---------------------------------------------------------------- CVE counts from the vulnerability records
X = sorted(R.rows('exploit_cves'), key=lambda r: (r['cveId'], r['coreDefenderApplicationId']))
by_id = {r['id']: r for r in V}
x_unmatched = R.fact('cves.exploitRecordsNotMatched', sum(1 for r in X if r['coreDefenderApplicationId'] not in by_id), 'exploit_cves + vulnerable_software')
cve_rows = R.fact('cves.summary', {
    'All CVEs': {'distinct': distinct('cves_by_id'), 'records': R.total('cves_by_severity'), **all_v},
    'Rated Critical by Defender': {'distinct': distinct('critical_cves_by_id'), 'records': R.total('critical_cves_by_id'), **crit_v},
    f'CVSS {cvss(CVSS_MIN)} or higher': {'distinct': distinct('cvss9_cves_by_id'), 'records': R.total('cvss9_cves_by_id'), **c9_v},
    'Public exploit available': {'distinct': len({r['cveId'] for r in X}), 'records': R.total('exploit_cves'), **exp_v}},
    'cves_by_id, critical_cves_by_id, cvss9_cves_by_id, exploit_cves, cves_by_severity + vulnerable_software + high_impact_devices')
sev_b = R.buckets('cves_by_severity')
sev_counts = R.fact('cves.bySeverity', {SEV_LABEL.get(s, s): sev_b.get(s, 0) for s in SEVERITY + sorted(k for k in sev_b if k not in SEVERITY)},
                    'cves_by_severity')
no_kb = R.fact('cves.noKnowledgeBaseEntry', R.IN['cves_by_exploit'].get('nullOrMissingCount', 0), 'cves_by_exploit')


# ---------------------------------------------------------------- tables
def software_groups(rows):
    g = defaultdict(list)
    for r in rows:
        g[(r['softwareName'], r['softwareVendor'])].append(r)
    return g


def sw_cell(name, vendor):
    return {'text': R.D(name), 'sub': R.D(vendor)}


# Software with a Critical CVE, a CVSS score at or above the line, or a public exploit: one row per name.
flagged = []
for (name, vendor), rs in software_groups([r for r in V if r['_any']]).items():
    devs = {k for r in rs for k in r['_devs']}
    flagged.append({'name': name, 'vendor': vendor, 'versions': len(rs), 'devices': len(devs), 'hi': hi_count(devs),
                    'crit': sum(r['_crit'] for r in rs), 'c9': sum(r['_c9'] for r in rs), 'exp': sum(r['_exp'] for r in rs),
                    'cvss': max(float(r.get('defenderApplication_maxCvssScore') or 0) for r in rs)})
flagged.sort(key=lambda s: (-s['devices'], -s['versions'], s['name'], s['vendor']))
R.fact('software.flagged', {f"{s['vendor']}:{s['name']}": {k: s[k] for k in ('versions', 'devices', 'hi', 'crit', 'c9', 'exp', 'cvss')} for s in flagged},
       'vulnerable_software + high_impact_devices')
flagged_reach = R.fact('software.flaggedReach', reach([r for r in V if r['_any']]), 'vulnerable_software + high_impact_devices')

# Most widespread software with any CVE: one row per name.
spread = []
for (name, vendor), rs in software_groups(V).items():
    devs = {k for r in rs for k in r['_devs']}
    spread.append({'name': name, 'vendor': vendor, 'versions': len(rs), 'devices': len(devs), 'hi': hi_count(devs),
                   'sev': min((r.get('defenderApplication_maxSeverity') or 'Unknown' for r in rs), key=sev_rank),
                   'cvss': max(float(r.get('defenderApplication_maxCvssScore') or 0) for r in rs)})
spread.sort(key=lambda s: (-s['devices'], -s['versions'], s['name'], s['vendor']))
names_with_cves = R.fact('software.namesWithCves', len(spread), 'vulnerable_software')
spread = spread[:TOP_SOFTWARE]
R.fact('software.widespread', {f"{s['vendor']}:{s['name']}": {'versions': s['versions'], 'devices': s['devices'], 'hi': s['hi'],
                                                               'severity': s['sev'], 'cvss': s['cvss']} for s in spread},
       'vulnerable_software + high_impact_devices')

# CVEs with a public exploit: one row per CVE.
xg = defaultdict(list)
for r in X:
    xg[r['cveId']].append(r)
xrows = []
for cve, rs in xg.items():
    sw = defaultdict(set)
    devs = set()
    for r in rs:
        a = by_id.get(r['coreDefenderApplicationId'])
        if a:
            sw[(a['softwareName'], a['softwareVendor'])].add(a['softwareVersion'])
            devs.update(a['_devs'])
        else:
            sw[(r['productCodeCpe'], '')].add('')
    scores = [float(r['deviceTvmSoftwareVulnerabilityDetails.cvssScore']) for r in rs if r.get('deviceTvmSoftwareVulnerabilityDetails.cvssScore') not in (None, '')]
    dates = sorted(d for d in (us_date(r.get('deviceTvmSoftwareVulnerabilityDetails.publishedDate')) for r in rs) if d)
    xrows.append({'cve': R.D(cve), 'sev': min((r['vulnerabilitySeverityLevel'] for r in rs), key=sev_rank),
                  'cvss': max(scores) if scores else None, 'published': dates[0] if dates else None,
                  'software': '; '.join(f'{R.D(nm)} ' + ', '.join(R.D(v) for v in sorted(vs) if v) if any(vs) else R.D(nm)
                                        for (nm, _), vs in sorted(sw.items())).strip(),
                  'devices': len(devs), 'hi': hi_count(devs)})
xrows.sort(key=lambda x: (sev_rank(x['sev']), -(x['cvss'] or 0), -x['devices'], x['cve']))
R.fact('cves.exploitList', {x['cve']: {'severity': x['sev'], 'cvss': x['cvss'], 'published': x['published'], 'devices': x['devices'], 'hi': x['hi']}
                            for x in xrows}, 'exploit_cves + vulnerable_software + high_impact_devices')

# End of support: every entry Defender gives an end-of-support status.
E.sort(key=lambda r: (EOS_ORDER.index(r['endOfSupportStatus']) if r['endOfSupportStatus'] in EOS_ORDER else 99, r['endOfSupportStatus'],
                      str(r.get('endOfSupportDate') or ''), r['softwareName'], r['softwareVersion'], r['osPlatform'], r['osArchitecture']))
R.fact('eos.list', [{'software': r['softwareName'], 'version': r['softwareVersion'], 'status': r['endOfSupportStatus'],
                     'date': str(r.get('endOfSupportDate') or '')[:10], 'devices': r['deviceCount'], 'hi': hi_count(r['_devs'])} for r in E],
       'eos_software + high_impact_devices')

# High-impact devices that carry a Critical CVE, a public exploit or end-of-support software.
hi_in = sorted(k for k in HI if k in record_ids) if records_whole else None
hi_stats = {k: DEV.get(k) or {'cve': 0, 'crit': 0, 'c9': 0, 'exp': 0, 'eos': 0, 'upcoming': 0} for k in HI}
carriers = [k for k in HI if hi_stats[k]['crit'] or hi_stats[k]['exp'] or hi_stats[k]['eos']]


def exposure(k):
    return HI[k].get('defenderDevice.exposureLevel')


def exposure_rank(k):
    lv = exposure(k)
    return EXPOSURE_ORDER.index(lv) if lv in EXPOSURE_ORDER else len(EXPOSURE_ORDER)


carriers.sort(key=lambda k: (0 if hi_stats[k]['crit'] or exposure(k) == 'High' else 1, exposure_rank(k), -hi_stats[k]['crit'],
                             -hi_stats[k]['exp'], -hi_stats[k]['eos'], str(HI[k].get('displayName') or '').lower(), k))
R.fact('highImpact.devices', [{'device': HI[k].get('displayName'), 'owner': HI[k].get('owner'), 'reason': impact_reason(HI[k]),
                               'exposureLevel': exposure(k), **{c: hi_stats[k][c] for c in ('crit', 'exp', 'eos', 'upcoming')}}
                              for k in carriers], 'high_impact_devices + vulnerable_software + eos_software')
hi_summary = R.fact('highImpact.summary', {
    'marked': len(HI), 'inDefenderInventory': len(hi_in) if hi_in is not None else None, 'carrying': len(carriers),
    'critical': sum(1 for k in HI if hi_stats[k]['crit']), 'exploit': sum(1 for k in HI if hi_stats[k]['exp']),
    'endOfSupport': sum(1 for k in HI if hi_stats[k]['eos']),
    'highExposure': sum(1 for k in carriers if exposure(k) == 'High')},
    'high_impact_devices + software_device_records + vulnerable_software + eos_software')

# ---------------------------------------------------------------- KPI facts
kpi_crit = R.fact('kpi.devicesWithCritical', crit_v['devices'], 'vulnerable_software')
kpi_exp = R.fact('kpi.exploitCves', cve_rows['Public exploit available']['distinct'], 'exploit_cves')
kpi_eos = R.fact('kpi.devicesWithEos', eos_v['devices'], 'eos_software')
R.fact('kpi.reach', {'critical': crit_v, 'exploit': exp_v, 'eos': eos_v, 'eosAny': eos_any, 'upcoming': upcoming},
       'vulnerable_software + eos_software + high_impact_devices')
eos_foot = f'Software versions at end of support: {n(eos_v["versions"])}'
if upcoming['versions']:
    eos_foot += f'. Upcoming end of support: {plural(upcoming["versions"], "version")} on {plural(upcoming["devices"], "device")}'
hi_foot = (f'Of {plural(hi_summary["inDefenderInventory"], "high-impact device")} in Defender’s software inventory. '
           if hi_in is not None else '')
hi_foot += f'With a public exploit: {n(hi_summary["exploit"])}. With end-of-support software: {n(hi_summary["endOfSupport"])}'

# ---------------------------------------------------------------- sections
R.hero(f'Software inventory, CVEs, end-of-support software, high-impact devices and installed software findings in the '
       f'{R.tenant_raw} Microsoft 365 tenant, from data collected on {R.as_of}.',
       scope=[('Devices', n(d_devices), f'In Defender’s software inventory; {n(i_devices)} in Intune discovered apps'),
              ('Software versions', n(entries), f'Defender entries; {n(ientries)} Intune discovered apps'),
              ('Software names', n(names), f'In Defender’s inventory; {n(inames)} in Intune’s'),
              ('Vendors', n(vendors), f'In Defender’s inventory; {n(publishers)} Intune publishers')])
of_dev = f' of {n(d_devices)}'
R.kpis([
    {'kicker': 'Open installed software findings', 'value': n(open_total),
     'foot': '. '.join(f'{k}: {n(v)}' for k, v in open_by_check.items())},
    {'kicker': 'Devices with a Critical CVE', 'value': n(kpi_crit), 'unit': of_dev,
     'foot': f'Software versions with a CVE Defender rates Critical: {n(crit_v["versions"])}'},
    {'kicker': 'High-impact devices with a Critical CVE', 'value': n(hi_summary['critical']),
     'unit': f' of {n(hi_summary["inDefenderInventory"])}' if hi_in is not None else None, 'foot': hi_foot},
    {'kicker': 'CVEs with a public exploit', 'value': n(kpi_exp),
     'foot': f'In {plural(exp_v["versions"], "software version")} on {plural(exp_v["devices"], "device")}'},
    {'kicker': 'Devices with end-of-support software', 'value': n(kpi_eos), 'unit': of_dev, 'foot': eos_foot},
])
R.findings('software_findings_open', 'software_findings_accepted', ['InstalledSoftware'], 'Installed software findings')

snap = R.IN['secure_score'].get('snapshot') or {}  # a tenant can have no snapshot yet
lv = EXPOSURE_LEVELS
extra = ([('Defender exposure score', snap['defenderExposureScore'], snap.get('maxDefenderExposureScore') or lv['high'][1],
           f'Defender Vulnerability Management, {lv["low"][0]} to {lv["high"][1]}. Microsoft’s levels: '
           f'{lv["low"][0]} to {lv["low"][1]} low, {lv["medium"][0]} to {lv["medium"][1]} medium, {lv["high"][0]} to {lv["high"][1]} high.')]
         if snap.get('defenderExposureScore') is not None else [])
_, ctl = R.secure_score('secure_score', 'secure_score_controls', 'device',
                        'Recommended actions in Microsoft’s Device category whose Defender Vulnerability Management recommendation is in the Application category',
                        extra=extra)
if ctl:
    rec = R.fact('secureScore.recommendations', {c['id']: {'exposed': c.get('securityCenterRecommendation.exposedMachinesCount'),
                                                           'assessed': c.get('securityCenterRecommendation.totalMachineCount')} for c in ctl},
                 'secure_score_controls')
    count = lambda v: n(v) if v is not None else 'Not reported'
    R.S[-1]['panels'].append({
        'kicker': 'Defender recommendation behind each action',
        'cols': [{'key': 'title', 'label': 'Recommended action'}, {'key': 'component', 'label': 'Related component'},
                 {'key': 'exposed', 'label': 'Exposed devices', 'n': True}, {'key': 'assessed', 'label': 'Devices assessed', 'n': True}],
        'rows': [{'title': {'text': R.D(c['title'])}, 'component': {'text': R.D(c.get('securityCenterRecommendation.relatedComponent') or 'No related component')},
                  'exposed': count(rec[c['id']]['exposed']), 'assessed': count(rec[c['id']]['assessed'])} for c in ctl],
        'note': 'From the Defender Vulnerability Management recommendation matched to each action: the product it applies to, '
                'the devices exposed to it and the devices Defender assessed. Defender reports these counts separately from Secure Score.'})

# High-impact devices
hi_note = ('High impact: the device record’s impact sources. A device inherits the mark from its primary user, with the '
           'user’s reason in parentheses (a privileged directory role, the org chart, or a technician’s mark), or a technician '
           'marks the device itself. Exposure level: Defender’s rating of the device from its pending security recommendations, '
           'with the device inventory’s label. Critical, Public exploit and End of support count software versions on the device. '
           'Devices with a Critical CVE or a High exposure level come first, then by exposure level and those counts.')
if hi_in is not None:
    hi_note += (f' High-impact devices in Defender’s software inventory: {n(hi_summary["inDefenderInventory"])} of '
                f'{n(hi_summary["marked"])} marked; the rest report no software to Defender.')
hi_rows = [{'device': {'text': R.D(HI[k].get('displayName') or k), 'sub': R.D(HI[k].get('owner') or 'No primary user')},
            'reason': {'text': impact_reason(HI[k])},
            'exposure': (label_cell(R.D(EXPOSURE_LABEL.get(exposure(k), exposure(k))), exposure(k)) if exposure(k)
                         else {'text': 'Not reported'}),
            'crit': n(hi_stats[k]['crit']), 'exp': n(hi_stats[k]['exp']),
            'eos': ({'text': n(hi_stats[k]['eos']), 'sub': f'Upcoming: {n(hi_stats[k]["upcoming"])}'} if hi_stats[k]['upcoming']
                    else n(hi_stats[k]['eos']))} for k in carriers]
R.add({'type': 'panels', 'kicker': 'High impact', 'title': 'High-impact devices with a Critical CVE, a public exploit or end-of-support software',
       'cols': 1, 'panels': [{
           'kicker': f'High-impact devices: {n(len(carriers))}'
                     + (f' of {n(hi_summary["inDefenderInventory"])} in Defender’s software inventory' if hi_in is not None else ''),
           'cols': [{'key': 'device', 'label': 'Device'}, {'key': 'reason', 'label': 'High impact'},
                    {'key': 'exposure', 'label': 'Exposure level'}, {'key': 'crit', 'label': 'Critical', 'n': True},
                    {'key': 'exp', 'label': 'Public exploit', 'n': True}, {'key': 'eos', 'label': 'End of support', 'n': True}],
           'rows': hi_rows,
           'note': (hi_note if hi_rows else 'No high-impact device in the collected data has a software version with a Critical CVE, '
                                            'a public exploit or an end-of-support status. ' + hi_note)}]}, 'high-impact-devices')

# A data view for each check, across every software version in Defender's inventory, zeros included.
R.add({'type': 'panels', 'kicker': 'Installed software checks', 'title': 'Software versions by severity, public exploit and end-of-support status',
       'cols': 1, 'panels': [
           {'kicker': f'Highest CVE severity: {n(entries)} software versions', 'bars': bars(list(sev_versions.items()), entries),
            'note': f'For the check {check_name[CHECK_CRITICAL]}. The highest Defender severity among the CVE records matched to each version: '
                    'Critical, High, Medium and Low are Defender’s values. Not yet rated: every matched CVE has an empty severity.'},
           {'kicker': f'Public exploit: {n(entries)} software versions', 'bars': bars(list(exp_versions.items()), entries),
            'note': f'For the check {check_name[CHECK_EXPLOIT]}. Public exploit: at least one CVE record matched to the version has '
                    'Defender’s IsExploitAvailable set.'},
           {'kicker': f'End-of-support status: {n(entries)} software versions', 'bars': bars(list(eos_versions.items()), entries),
            'note': f'For the checks {check_name[CHECK_EOS]} and {check_name[CHECK_UPCOMING]}. Bars carry the Defender portal’s tags; '
                    'Defender’s EndOfSupportStatus values, in the same order: ' + ', '.join(R.D(s) for s in eos_status) + '. No '
                    'end-of-support status: the value is empty. Microsoft shows upcoming tags up to six months before the date.'}]},
      'check-data')

# Inventory sources
inv_note = ('Defender: one entry per vendor, name and version on one OS platform and architecture, with vendors as Defender '
            'reports them; devices are the Defender machines that report software')
if d_unmatched:
    inv_note += f', of which {n(d_unmatched)} have no device record'
inv_note += ('. Intune: one entry per discovered app, with publishers as reported and the common name taken from '
             f'certificate-style names; {n(no_pub)} entries report no publisher; devices are those matched to a device record')
if i_unmatched:
    inv_note += f'; entries on a device with no device record: {n(i_unmatched)}, their devices not counted'
inv_note += '.'
R.add({'type': 'panels', 'kicker': 'Software inventory', 'title': 'Installed software as Defender and Intune report it', 'cols': 1, 'panels': [
    {'kicker': 'Inventory sources',
     'cols': [{'key': 'source', 'label': 'Source'}, {'key': 'entries', 'label': 'Entries', 'n': True},
              {'key': 'names', 'label': 'Software names', 'n': True}, {'key': 'vendors', 'label': 'Vendors or publishers', 'n': True},
              {'key': 'devices', 'label': 'Devices', 'n': True}],
     'rows': [{'source': {'text': R.D('Defender Vulnerability Management software inventory')}, 'entries': n(entries), 'names': n(names),
               'vendors': n(vendors), 'devices': n(d_devices)},
              {'source': {'text': R.D('Intune discovered apps')}, 'entries': n(ientries), 'names': n(inames),
               'vendors': n(publishers), 'devices': n(i_devices)}],
     'note': inv_note}]}, 'inventory-sources')

# CVE overview
summary_cols = [{'key': 'measure', 'label': 'CVEs'}, {'key': 'distinct', 'label': 'Distinct CVEs', 'n': True},
                {'key': 'records', 'label': 'CVE records', 'n': True}, {'key': 'versions', 'label': 'Software versions', 'n': True},
                {'key': 'devices', 'label': 'Devices', 'n': True}, {'key': 'highImpact', 'label': 'High-impact devices', 'n': True}]
R.add({'type': 'panels', 'kicker': 'Vulnerabilities', 'title': 'CVEs on installed software', 'cols': 1, 'panels': [
    {'kicker': 'CVEs by Defender rating, CVSS score and exploit',
     'cols': summary_cols,
     'rows': [{'measure': {'text': k}, **{c: n(v[c]) for c in ('distinct', 'records', 'versions', 'devices', 'highImpact')}} for k, v in cve_rows.items()],
     'note': 'A CVE record is one CVE on one software version. Software versions and devices count those with at least one such CVE; '
             'high-impact devices are the devices among them marked high impact. '
             f'CVE records with no Defender knowledge-base entry, so no CVSS score or exploit flag: {n(no_kb)}.'},
    {'kicker': f'CVE records by Defender severity: {n(cve_rows["All CVEs"]["records"])}',
     'bars': bars(list(sev_counts.items()), cve_rows['All CVEs']['records']),
     'note': 'Defender sets severity from the CVSS score and threat factors; Critical, High, Medium and Low are its values. '
             'Not yet rated: the CVE record has an empty severity.'}]}, 'cves')

# Software with Critical, CVSS at or above the line, or exploitable CVEs
flag_note = (f'One row per software name, with the vendor below it. Versions: those with a CVE Defender rates Critical, a CVSS score of '
             f'{cvss(CVSS_MIN)} or higher or a public exploit. Devices: devices with one of those versions; High-impact devices: those '
             f'among them marked high impact. Critical, CVSS {cvss(CVSS_MIN)}+ and Public exploit count versions. Sorted by devices, '
             'then versions, then name.')
R.add({'type': 'panels', 'kicker': 'Vulnerabilities', 'title': f'Software with Critical CVEs, CVSS {cvss(CVSS_MIN)} or higher, or public exploits',
       'cols': 1, 'panels': [{
           'kicker': f'Software names: {n(len(flagged))}, in {plural(flagged_reach["versions"], "version")} on {plural(flagged_reach["devices"], "device")}',
           'cols': [{'key': 'sw', 'label': 'Software'}, {'key': 'versions', 'label': 'Versions', 'n': True},
                    {'key': 'devices', 'label': 'Devices', 'n': True}, {'key': 'hi', 'label': 'High-impact devices', 'n': True},
                    {'key': 'crit', 'label': 'Critical', 'n': True}, {'key': 'c9', 'label': f'CVSS {cvss(CVSS_MIN)}+', 'n': True},
                    {'key': 'exp', 'label': 'Public exploit', 'n': True}, {'key': 'cvss', 'label': 'Highest CVSS', 'n': True}],
           'rows': [{'sw': sw_cell(s['name'], s['vendor']), 'versions': n(s['versions']), 'devices': n(s['devices']), 'hi': n(s['hi']),
                     'crit': n(s['crit']), 'c9': n(s['c9']), 'exp': n(s['exp']),
                     'cvss': cvss(s['cvss']) if s['cvss'] else 'No CVSS score'} for s in flagged],
           'note': flag_note if flagged else 'No software version in the collected data has a CVE rated Critical, a CVSS score of '
                                             f'{cvss(CVSS_MIN)} or higher or a public exploit.'}]}, 'critical-software')

# CVEs with a public exploit
x_note = ('CVEs Defender marks IsExploitAvailable: exploit code is publicly available. Severity is Defender’s rating; Published is the '
          'disclosure date Defender reports. High-impact devices: devices with an affected version that are marked high impact. '
          'Sorted by severity, then CVSS score, then devices.')
if x_unmatched:
    x_note += f' Exploit records not matched to a software version, listed by their vendor, name and version key: {n(x_unmatched)}.'
R.add({'type': 'panels', 'kicker': 'Vulnerabilities', 'title': f'CVEs with a public exploit: {n(len(xrows))}', 'cols': 1, 'panels': [{
    'kicker': f'In {plural(exp_v["versions"], "software version")} on {plural(exp_v["devices"], "device")}',
    'cols': [{'key': 'cve', 'label': 'CVE'}, {'key': 'sev', 'label': 'Severity'}, {'key': 'cvss', 'label': 'CVSS', 'n': True},
             {'key': 'pub', 'label': 'Published'}, {'key': 'sw', 'label': 'Software and versions'}, {'key': 'devices', 'label': 'Devices', 'n': True},
             {'key': 'hi', 'label': 'High-impact devices', 'n': True}],
    'rows': [{'cve': {'mono': x['cve']}, 'sev': sev_cell(x['sev']), 'cvss': cvss(x['cvss']) if x['cvss'] is not None else 'No CVSS score',
              'pub': esc(x['published']) if x['published'] else 'No published date', 'sw': {'text': x['software']},
              'devices': n(x['devices']), 'hi': n(x['hi'])} for x in xrows],
    'note': x_note if xrows else 'No CVE record in the collected data has Defender’s IsExploitAvailable set.'}]}, 'exploit-cves')


# End of support
def names_cell(r):
    """Device names, high-impact devices first and marked, for versions on few enough devices; otherwise counts."""
    devs = device_list(r)
    hi_names = sorted((R.D(name) for key, name in devs if key in HI), key=str.lower)
    others = sorted((R.D(name) for key, name in devs if key not in HI), key=str.lower)
    if len(devs) <= NAMES_UP_TO:
        return {'text': ', '.join([f'{x} (high impact)' for x in hi_names] + others)}
    return {'text': f'{plural(len(devs), "device")}' + (f', {n(len(hi_names))} high impact' if hi_names else '')}


R.add({'type': 'panels', 'kicker': 'End of support', 'title': f'Software versions with an end-of-support status: {n(len(E))}', 'cols': 1, 'panels': [{
    'kicker': f'On {plural(eos_any["devices"], "device")}, {n(eos_any["highImpact"])} of them high impact',
    'cols': [{'key': 'sw', 'label': 'Software'}, {'key': 'ver', 'label': 'Version'}, {'key': 'status', 'label': 'Defender tag'},
             {'key': 'date', 'label': 'End of support'}, {'key': 'devices', 'label': 'Devices', 'n': True}, {'key': 'names', 'label': 'Device names'}],
    'rows': [{'sw': sw_cell(r['softwareName'], r['softwareVendor']),
              'ver': {'mono': R.D(r['softwareVersion']),
                      'sub': ', '.join([platform(r['osPlatform'])] + ([R.D(r['osArchitecture'])] if r.get('osArchitecture') else []))},
              'status': label_cell(R.D(EOS_LABEL.get(r['endOfSupportStatus'], r['endOfSupportStatus'])), r['endOfSupportStatus']),
              'date': esc(R.D(str(r['endOfSupportDate'])[:10])) if r.get('endOfSupportDate') else 'No end-of-support date',
              'devices': n(r['deviceCount']), 'names': names_cell(r)} for r in E],
    'note': ('Defender tag: the portal’s tag, with Defender’s EndOfSupportStatus value beneath. End of support: Defender’s '
             f'EndOfSupportDate. Device names are listed for versions on {n(NAMES_UP_TO)} devices or fewer, high-impact devices first. '
             'Sorted by status, then date.') if E else
            'No software version in the collected data has an end-of-support status.'}]}, 'end-of-support')

# Most widespread software with CVEs
R.add({'type': 'panels', 'kicker': 'Software', 'title': 'Most widespread software with CVEs', 'cols': 1, 'panels': [{
    'kicker': f'Top {n(TOP_SOFTWARE)} of {n(names_with_cves)} software names with a version that has a CVE',
    'cols': [{'key': 'sw', 'label': 'Software'}, {'key': 'versions', 'label': 'Versions with CVEs', 'n': True},
             {'key': 'devices', 'label': 'Devices', 'n': True}, {'key': 'hi', 'label': 'High-impact devices', 'n': True},
             {'key': 'sev', 'label': 'Highest severity'}, {'key': 'cvss', 'label': 'Highest CVSS', 'n': True}],
    'rows': [{'sw': sw_cell(s['name'], s['vendor']), 'versions': n(s['versions']), 'devices': n(s['devices']), 'hi': n(s['hi']),
              'sev': sev_cell(s['sev']), 'cvss': cvss(s['cvss']) if s['cvss'] else 'No CVSS score'} for s in spread],
    'note': (f'The {n(TOP_SOFTWARE)} software names on the most devices in a version with a CVE; ties by versions, then name. '
             'Devices counts devices with one of those versions. Highest severity is Defender’s rating across the versions.')
            if spread else 'No software version in the collected data has a CVE record.'}]}, 'widespread-software')

R.footer(
    f'Read-only collection on {R.as_of}. Software comes from the Microsoft Defender Vulnerability Management software inventory and '
    'Intune discovered apps, CVEs from Defender’s vulnerability records for that software, and the high-impact mark and exposure level '
    'from device records. Every figure comes from that one collection. The same queries run for every tenant.',
    'A software version is one Defender inventory entry: one vendor, name and version on one OS platform and architecture. Severity is '
    'Defender’s VulnerabilitySeverityLevel. CVSS is the score Defender reports. A public exploit is Defender’s IsExploitAvailable. For each '
    'software version, the highest severity, highest CVSS score and exploit flag cover Defender’s CVE records for that vendor, name and '
    'version on any OS platform or architecture. A device is high impact when its record carries an impact source: inherited from its '
    'primary user, or marked by a technician.',
    'Defender inventory and CVEs on devices not onboarded to Defender for Endpoint. Unmanaged apps on personal devices, which Intune '
    'does not collect. Software versions and devices for CVEs on software that Defender’s inventory lists under a CPE name, because the '
    'vulnerability records do not match those entries. A Defender machine with no device record has no name, primary user or high-impact mark.')
R.write()
