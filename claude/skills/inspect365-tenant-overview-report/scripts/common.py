"""Shared pieces of the report recipes: run inputs, facts, and the sections every deep dive opens with.

A recipe's build.py:

    import pathlib, sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    from common import Report, esc, n
    R = Report(__file__, 'devices-deep-dive', '0.1.0', 'Devices report')
    ...                                   # compute facts from R.IN, register each with R.fact()
    R.hero(meta, chips)
    R.kpis(cards)
    R.findings('device_findings_open', 'device_findings_accepted', ['Device'], 'Device findings')
    R.secure_score('secure_score', 'secure_score_controls', 'device', 'Recommended actions in Microsoft’s Device category')
    R.add({...})                          # the area's own panels sections
    R.footer(method, definitions, not_counted)
    R.write()

Every deep dive opens with its findings, then Microsoft Secure Score (2026-10-06). Facts only
(README): every number shown goes through R.fact(), every data string through R.D(). The same inputs
always produce the same bytes.
"""
import datetime as dt, hashlib, html, json, pathlib, re, sys

STATUS_NOTE = 'Open means Needs Review or Flagged. Accepted means a reviewer set the finding to Accepted.'
# The product's asset type for each finding type.
ASSET = {'Identity': 'User', 'Group': 'Group', 'Device': 'Device', 'ServicePrincipal': 'Entra app',
         'InstalledSoftware': 'Installed software', 'Mailbox': 'Mailbox', 'Team': 'Team', 'SharePoint': 'SharePoint site'}
# Why the product marks a user or device high impact (system.impactSources[].sourceRule / type).
IMPACT_REASON = {'privilegedDirectoryRole': 'Privileged directory role', 'orgChart': 'Org chart',
                 'manualAssignment': 'Marked by a technician', 'inherited': 'Owner is high impact'}
# Secure Score snapshot field prefix -> Microsoft's category name.
PILLAR = {'identity': 'Identity', 'device': 'Device', 'app': 'Apps', 'data': 'Data'}
# Microsoft's product name for each licenseDetails skuPartNumber ("Product names and service plan identifiers for
# licensing", Learn 2026-10-07). A part number missing here shows as the part number.
SKU_NAME = {
    'SPB': 'Microsoft 365 Business Premium', 'O365_BUSINESS_PREMIUM': 'Microsoft 365 Business Standard',
    'O365_BUSINESS_ESSENTIALS': 'Microsoft 365 Business Basic', 'O365_BUSINESS': 'Microsoft 365 Apps for Business',
    'SMB_BUSINESS': 'Microsoft 365 Apps for Business', 'SMB_BUSINESS_ESSENTIALS': 'Microsoft 365 Business Basic',
    'SMB_BUSINESS_PREMIUM': 'Microsoft 365 Business Standard - Prepaid Legacy', 'SPE_E3': 'Microsoft 365 E3',
    'SPE_E5': 'Microsoft 365 E5', 'SPE_F1': 'Microsoft 365 F3', 'SPE_F5_SEC': 'Microsoft 365 F5 Security Add-on',
    'SPE_E5_NOPSTNCONF': 'Microsoft 365 E5 without Audio Conferencing', 'Microsoft_365_E3_(no_Teams)': 'Microsoft 365 E3 (no Teams)',
    'Microsoft_365_E5_(no_Teams)': 'Microsoft 365 E5 (no Teams)', 'O365_w/o_Teams_Bundle_M5': 'Microsoft 365 E5 EEA (no Teams)',
    'M365_F1': 'Microsoft 365 F1', 'M365_F1_COMM': 'Microsoft 365 F1',
    'DEVELOPERPACK_E5': 'Microsoft 365 E5 Developer (without Windows and Audio Conferencing)',
    'ENTERPRISEPACK': 'Office 365 E3', 'STANDARDPACK': 'Office 365 E1', 'ENTERPRISEPREMIUM': 'Office 365 E5',
    'ENTERPRISEPREMIUM_NOPSTNCONF': 'Office 365 E5 without Audio Conferencing', 'DESKLESSPACK': 'Office 365 F3',
    'Office_365_E1_(no_Teams)': 'Office 365 E1 (no Teams)', 'Office_365_E3_(no_Teams)': 'Office 365 E3 (no Teams)',
    'EXCHANGESTANDARD': 'Exchange Online (Plan 1)', 'EXCHANGEENTERPRISE': 'Exchange Online (PLAN 2)',
    'EXCHANGEDESKLESS': 'Exchange Online Kiosk', 'EXCHANGEARCHIVE_ADDON': 'Exchange Online Archiving for Exchange Online',
    'EXCHANGEARCHIVE': 'Exchange Online Archiving for Exchange Server', 'EXCHANGE_S_ESSENTIALS': 'Exchange Online Essentials',
    'EXCHANGESTANDARD_ALUMNI': 'Exchange Online (Plan 1) for Alumni with Yammer',
    'AAD_PREMIUM': 'Microsoft Entra ID P1', 'AAD_PREMIUM_P2': 'Microsoft Entra ID P2',
    'Microsoft_Entra_ID_Governance': 'Microsoft Entra ID Governance', 'EMS': 'Enterprise Mobility + Security E3',
    'EMSPREMIUM': 'Enterprise Mobility + Security E5', 'INTUNE_A': 'Intune',
    'ATP_ENTERPRISE': 'Microsoft Defender for Office 365 (Plan 1)', 'THREAT_INTELLIGENCE': 'Microsoft Defender for Office 365 (Plan 2)',
    'DEFENDER_ENDPOINT_P1': 'Microsoft Defender for Endpoint P1', 'WIN_DEF_ATP': 'Microsoft Defender for Endpoint',
    'MDATP_XPLAT': 'Microsoft Defender for Endpoint P2_XPLAT', 'MDE_SMB': 'Microsoft Defender for Business',
    'IDENTITY_THREAT_PROTECTION': 'Microsoft Defender Suite', 'INFORMATION_PROTECTION_COMPLIANCE': 'Microsoft 365 E5 Compliance',
    'M365_E5_SUITE_COMPONENTS': 'Microsoft 365 E5 Extra Features', 'RIGHTSMANAGEMENT': 'Azure Information Protection Plan 1',
    'RIGHTSMANAGEMENT_ADHOC': 'Rights Management Adhoc',
    'Microsoft_Teams_Enterprise_New': 'Microsoft Teams Enterprise', 'Microsoft_Teams_Premium': 'Microsoft Teams Premium Introductory Pricing',
    'Teams_Ess': 'Microsoft Teams Essentials', 'TEAMS_ESSENTIALS_AAD': 'Microsoft Teams Essentials (Microsoft Entra identity)',
    'Microsoft_Teams_Exploratory_Dept': 'Microsoft Teams Exploratory Dept', 'TEAMS_EXPLORATORY': 'Microsoft Teams Exploratory',
    'TEAMS_FREE': 'Microsoft Teams (Free)', 'MCOEV': 'Microsoft Teams Phone Standard', 'MCOMEETADV': 'Microsoft 365 Audio Conferencing',
    'MCOPSTN1': 'Skype for Business PSTN Domestic Calling', 'MCOPSTN2': 'Skype for Business PSTN Domestic and International Calling',
    'MCOPSTN_5': 'Microsoft 365 Domestic Calling Plan (120 min)', 'MCOPSTNC': 'Communications Credits',
    'Microsoft_Teams_Calling_Plan_pay_as_you_go_(country_zone_1_US)': 'Microsoft Teams Calling Plan pay-as-you-go (country/region zone 1 - US)',
    'PHONESYSTEM_VIRTUALUSER': 'Microsoft Teams Phone Resource Account', 'MCOCAP': 'Microsoft Teams Shared Devices',
    'MEETING_ROOM': 'Microsoft Teams Rooms Standard', 'Microsoft_Teams_Rooms_Pro': 'Microsoft Teams Rooms Pro',
    'Microsoft_Teams_Rooms_Basic': 'Microsoft Teams Rooms Basic',
    'Microsoft_Teams_Rooms_Pro_without_Audio_Conferencing': 'Microsoft Teams Rooms Pro without Audio Conferencing',
    'Microsoft_365_Copilot': 'Copilot for Microsoft 365', 'CCIBOTS_PRIVPREV_VIRAL': 'Microsoft Copilot Studio Viral Trial',
    'FLOW_FREE': 'Microsoft Power Automate Free', 'FLOW_PER_USER': 'Power Automate per user plan',
    'POWERAUTOMATE_ATTENDED_RPA': 'Power Automate Premium', 'POWERAPPS_PER_USER': 'Power Apps Premium',
    'POWERAPPS_VIRAL': 'Microsoft Power Apps Plan 2 Trial', 'POWERAPPS_DEV': 'Microsoft PowerApps for Developer',
    'POWER_BI_STANDARD': 'Microsoft Fabric (Free)', 'POWER_BI_PRO': 'Power BI Pro', 'PBI_PREMIUM_PER_USER': 'Power BI Premium Per User',
    'PBI_PREMIUM_PER_USER_ADDON': 'Power BI Premium Per User Add-On', 'FORMS_PRO': 'Dynamics 365 Customer Voice Trial',
    'PROJECTPREMIUM': 'Project Online Premium', 'PROJECTPROFESSIONAL': 'Planner and Project Plan 3', 'PROJECT_P1': 'Planner Plan 1',
    'PROJECTESSENTIALS': 'Project Online Essentials', 'VISIOCLIENT': 'Visio Plan 2', 'VISIOONLINE_PLAN1': 'Visio Plan 1',
    'STREAM': 'Microsoft Stream', 'VIVA': 'Microsoft Viva Suite', 'WINDOWS_STORE': 'Windows Store for Business',
    'MICROSOFT_BUSINESS_CENTER': 'Microsoft Business Center', 'WIN10_VDA_E3': 'WINDOWS 10/11 ENTERPRISE E3',
    'CPC_E_2C_8GB_128GB': 'Windows 365 Enterprise 2 vCPU 8 GB 128 GB', 'CPC_E_4C_16GB_128GB': 'Windows 365 Enterprise 4 vCPU 16 GB 128 GB',
    'CPC_E_8C_32GB_512GB': 'Windows 365 Enterprise 8 vCPU 32 GB 512 GB',
    'DYN365_ENTERPRISE_CUSTOMER_SERVICE': 'Dynamics 365 for Customer Service Enterprise Edition',
    'DYN365_ENTERPRISE_SALES': 'Dynamics 365 for Sales Enterprise Edition', 'DYNAMICS_365_CONTACT_CENTER': 'Dynamics 365 Contact Center',
    'D365_SALES_PRO': 'Dynamics 365 for Sales Professional', 'D365_SALES_PRO_IW': 'Dynamics 365 for Sales Professional Trial',
    'DYN365_BUSCENTRAL_PREMIUM': 'Dynamics 365 Business Central Premium', 'DYN365_BUSCENTRAL_ESSENTIAL': 'Dynamics 365 Business Central Essentials',
    'DYN365_TEAM_MEMBERS': 'Dynamics 365 Team Members_wDynamicsRetail',
    'PROJECT_MADEIRA_PREVIEW_IW_SKU': 'Dynamics 365 Business Central for IWs', 'INTUNE_A_D': 'Microsoft Intune Device',
    'Microsoft_Intune_Suite': 'Microsoft Intune Suite', 'SPZA_IW': 'App Connect IW',
    'DYN365_AI_SERVICE_INSIGHTS': 'Dynamics 365 Customer Service Insights Trial', 'CDSAICAPACITY': 'AI Builder Capacity add-on',
    'Power_Virtual_Agents': 'Microsoft Copilot Studio', 'DYN365_ENTERPRISE_P1_IW': 'Dynamics 365 P1 Trial for Information Workers',
    'Microsoft365_Lighthouse': 'Microsoft 365 Lighthouse', 'Power_Pages_vTrial_for_Makers': 'Power Pages vTrial for Makers'}


def sku(s):
    """A licenseDetails or subscribedSkus part number without the zero-width spaces Graph sometimes returns."""
    return str(s).replace('​', '').strip()

esc = lambda s: html.escape(str(s), quote=False)
n = lambda x: f'{x:,}'


def num(x):
    """Points as Microsoft reports them, to two decimals at most: 1,028.67, 64.4, 1,509."""
    x = round(float(x), 2)
    return f'{x:,.2f}'.rstrip('0').rstrip('.')


def width(x, of):
    """Bar width in percent (a layout value, not shown as text)."""
    return round(100 * x / of, 1) if of else 0


ISO_FRACTION = re.compile(r'(T\d{2}:\d{2}:\d{2})\.(\d+)')


def iso(s):
    """dt.datetime.fromisoformat for Microsoft's timestamps on Python 3.9 and 3.10 as well, which read only 3 or 6
    fractional digits and no Z (macOS's own python3 is 3.9): the fraction is cut or padded to 6 digits, Z becomes
    +00:00, and a value without a zone stays without one."""
    s = ISO_FRACTION.sub(lambda m: f'{m.group(1)}.{m.group(2)[:6].ljust(6, "0")}', str(s).replace('Z', '+00:00'), count=1)
    return dt.datetime.fromisoformat(s)


class Report:
    def __init__(self, recipe_file, recipe, version, title):
        if len(sys.argv) < 2:
            sys.exit(f'usage: python3 {recipe_file} <run-dir>')
        self.here = pathlib.Path(recipe_file).resolve().parent
        self.run_dir = pathlib.Path(sys.argv[1]).resolve()
        self.run = json.load(open(self.run_dir / 'run.json'))
        self.spec = json.load(open(self.here / 'recipes.json'))[self.run['recipeDir']]
        self.recipe, self.version, self.title = recipe, version, title
        self.IN = {}
        for q in self.spec['queries']:
            p = self.run_dir / 'inputs' / f"{q['id']}.json"
            if not p.exists():
                sys.exit(f'missing input {p.name}: run query {q["id"]} first')
            data = json.load(open(p))
            if q['tool'] == 'query' and 'resultCount' in data and data['resultCount'] != data.get('totalCount'):
                sys.exit(f'{q["id"]} holds {data["resultCount"]} of {data["totalCount"]} rows; save every page before building')
            self.IN[q['id']] = data
        self.digest = hashlib.sha256(json.dumps(self.IN, sort_keys=True).encode()).hexdigest()
        self.as_of = self.run['asOf']
        self.AS_OF = dt.datetime.fromisoformat(self.as_of + 'T23:59:59+00:00')
        self.FACTS, self.STRINGS, self.S = {}, set(), []
        self.tenant_raw = self.run['tenantName']
        self.tenant = esc(self.D(self.tenant_raw))
        self.D(self.run['tenantId'])

    # ------------------------------------------------------------ facts and data strings
    def fact(self, name, value, source):
        self.FACTS[name] = {'value': value, 'source': source}
        return value

    def D(self, s):
        """A string from the data or Microsoft's vocabulary; recorded so the fact check can tell it from template text."""
        self.STRINGS.add(str(s))
        return str(s)

    # ------------------------------------------------------------ inputs
    def rows(self, qid):
        return self.IN[qid].get('results', [])

    def buckets(self, qid):
        return {str(b['value']): b['count'] for b in self.IN[qid].get('results', [])}

    def total(self, qid):
        return self.IN[qid].get('totalCount', 0)

    @staticmethod
    def when(s):
        return iso(s) if s else None

    def age(self, d):
        return None if d is None else (self.AS_OF - d).days

    @staticmethod
    def day(d, none='None on record'):
        """A date, or the label for no date: pass none='Never signed in' for sign-in fields (2026-10-07)."""
        return d.strftime('%Y-%m-%d') if d else none

    def state(self, label, raw, source):
        """A table cell for a state a source reports: Microsoft's label, with the source's own value beneath it,
        such as Not encrypted over 'Intune: notEncrypted' (2026-10-07)."""
        return {'text': self.D(label), 'sub': f'{source}: {self.D(raw)}'}

    # ------------------------------------------------------------ sections
    def add(self, section, id=None):
        """Add a section. id lets a run leave it out: run.json "omit": [ids] (customers who don't want a section)."""
        if id:
            section['id'] = id
        self.S.append(section)

    def hero(self, meta, chips=(), scope=()):
        """The title band. scope: the working set as (label, value) or (label, value, note) rows, shown as large
        figures beside the title so the reader sees what the report covers (2026-10-07)."""
        h = {'type': 'hero', 'eyebrow': f'{self.title} · {self.as_of}', 'h1': self.tenant_raw, 'meta': meta}
        if scope:
            h['scope'] = [dict(zip(('label', 'value', 'sub'), row)) for row in scope]
        if chips:
            h['chips'] = list(chips)
        self.add(h, 'hero')

    def kpis(self, cards):
        self.add({'type': 'kpiStrip', 'cards': cards}, 'kpis')

    def findings(self, open_q, accepted_q, types, title, key='findings', defs_q='definitions', only=None):
        """Every finding check for the area's asset types: those with open or accepted findings first, by
        open count, then the checks with none. only: definition ids, for an area such as Conditional Access that has
        no asset type of its own; its finding queries must filter findingId to the same ids.
        Returns (open count by type, open by findingId, accepted by findingId)."""
        defs = [d for d in self.IN[defs_q]['definitions'] if d['type'] in types and (only is None or d['id'] in only)]
        if only is not None and len(defs) != len(set(only)):
            sys.exit(f'only names ids that are not {"/".join(types)} definitions: {sorted(set(only) - {d["id"] for d in defs})}')
        defs.sort(key=lambda d: (types.index(d['type']), d['orderId'], d['displayName']))
        ids = {d['id'] for d in defs}
        o, a = self.buckets(open_q), self.buckets(accepted_q)
        unknown = sorted(f for f in {*o, *a} if f not in ids)
        if unknown:
            sys.exit(f'{open_q}/{accepted_q} hold finding ids with no {"/".join(types)} definition: {unknown}')
        hit = sorted((d for d in defs if o.get(d['id'], 0) or a.get(d['id'], 0)),
                     key=lambda d: (-o.get(d['id'], 0), -a.get(d['id'], 0), types.index(d['type']), d['orderId']))
        quiet = [d for d in defs if d not in hit]
        by_type = {t: sum(o.get(d['id'], 0) for d in defs if d['type'] == t) for t in types}
        self.fact(key, {d['displayName']: {'open': o.get(d['id'], 0), 'accepted': a.get(d['id'], 0)} for d in defs},
                  f'{open_q} + {accepted_q} + {defs_q}')
        self.fact(f'{key}.checks', {'checks': len(defs), 'withFindings': len(hit), 'without': len(quiet)}, defs_q)
        self.fact(f'{key}.openByType', by_type, open_q)
        multi = len(types) > 1
        head = [{'key': 'finding', 'label': 'Finding'}] + ([{'key': 'asset', 'label': 'Asset type'}] if multi else [])
        head.append({'key': 'checks', 'label': 'What it checks'})

        waits = {d['displayName']: d['observationWindowDays'] for d in defs if d.get('observationWindowDays')}
        if waits:
            self.fact(f'{key}.observationWindowDays', waits, defs_q)

        def row(d, counts):
            r = {'finding': {'text': self.D(d['displayName'])}, 'checks': {'text': self.D(d['description'])}}
            if d.get('observationWindowDays'):  # matches stay hidden (Detected) until the window ends
                r['checks']['sub'] = f"Counted once the condition has lasted {n(d['observationWindowDays'])} days."
            if multi:
                r['asset'] = {'text': ASSET.get(d['type'], d['type'])}
            if counts:
                r.update({'open': n(o.get(d['id'], 0)), 'acc': n(a.get(d['id'], 0))})
            return r

        panels = []
        if hit:
            panels.append({'kicker': f'Checks with open or accepted findings: {n(len(hit))} of {n(len(defs))}',
                           'cols': head + [{'key': 'open', 'label': 'Open', 'n': True}, {'key': 'acc', 'label': 'Accepted', 'n': True}],
                           'rows': [row(d, True) for d in hit], 'note': STATUS_NOTE})
        if quiet:
            panels.append({'kicker': f'Nothing detected: {n(len(quiet))} of {n(len(defs))} checks',
                           'cols': head, 'rows': [row(d, False) for d in quiet],
                           'note': 'These checks found no matching objects in the collected data.'
                                   + (' A check with a waiting period counts a match only once the condition has lasted that long,'
                                      ' so in a tenant\u2019s first days those checks show nothing.' if any(d['displayName'] in waits for d in quiet) else '')})
        self.add({'type': 'panels', 'kicker': 'Findings', 'title': title, 'cols': 1, 'panels': panels}, 'findings')
        return by_type, o, a

    def secure_score(self, snapshot_q, controls_q, pillar, scope, key='secureScore', extra=()):
        """Microsoft Secure Score: the tenant score, the area's category (pillar: identity, device, app, data or
        None) and the controls the recipe scoped (scope says which, in words) that earn less than their maximum.
        extra: (label, value, max, note) rows such as the Defender exposure score."""
        snap = self.IN[snapshot_q].get('snapshot') or {}
        taken = self.D(str(snap['createdDateTime'])[:10]) if snap.get('createdDateTime') else None
        measures = [('Overall', 'the overall score', 'currentScore', 'maxScore', 'scorePercentage')]
        if pillar:
            P = pillar[0].upper() + pillar[1:]
            measures.append((f'{PILLAR[pillar]} category', f'the {PILLAR[pillar]} category', f'{pillar}Score', f'max{P}Score',
                             f'{pillar}ScorePercentage'))
        # As in the tenant overview, a measure shows only with its points, maximum and percent: a snapshot can hold no
        # maximum for a category (a Device category, 2026-10-19), and the server gives a missing score 0%.
        lines = [(label, snap[s], snap[m], snap[p]) for label, _, s, m, p in measures
                 if snap.get(s) is not None and snap.get(m) is not None and snap.get(p) is not None]
        left_out = [name for label, name, *_ in measures if label not in {line[0] for line in lines}]
        shown = {label: {'points': round(float(s), 2), 'max': round(float(m), 2), 'percent': round(100 * float(p), 1)}
                 for label, s, m, p in lines}
        self.fact(key, shown, snapshot_q)
        score_rows = [{'measure': {'text': label}, 'points': num(s), 'max': num(m), 'percent': f'{round(100 * float(p), 1)}%'}
                      for label, s, m, p in lines]
        for label, v, m, note in extra:
            self.fact(f'{key}.{label}', {'value': round(float(v), 1), 'max': m}, snapshot_q)
            score_rows.append({'measure': {'text': label, 'sub': note} if note else {'text': label},
                               'points': num(round(float(v), 1)), 'max': num(m), 'percent': '—'})
        ctl = [c for c in self.rows(controls_q) if c.get('controlScore.score') is not None and c.get('maxScore')]
        ctl = [c for c in ctl if float(c['controlScore.score']) < float(c['maxScore'])]
        ctl.sort(key=lambda c: (-(float(c['maxScore']) - float(c['controlScore.score'])), c.get('rank') or 999, c['title']))
        self.fact(f'{key}.controls', {c['id']: {'points': round(float(c['controlScore.score']), 2), 'max': round(float(c['maxScore']), 2)}
                                      for c in ctl}, controls_q)
        gap = (f'The latest snapshot has no complete score for {" or ".join(left_out)}, so '
               f'{"it isn’t" if len(left_out) == 1 else "neither is"} shown.')
        if not snap:
            note = 'No Secure Score snapshot has been collected for this tenant yet.'
        elif not lines:
            note = gap
        else:
            note = 'As Microsoft reports it. The maximum depends on the tenant’s licenses and services.' + (f' {gap}' if left_out else '')
        panels = [{'kicker': f'Microsoft Secure Score on {taken}' if taken else 'Microsoft Secure Score',
                   'cols': [{'key': 'measure', 'label': 'Measure'}, {'key': 'points', 'label': 'Points', 'n': True},
                            {'key': 'max', 'label': 'Maximum', 'n': True}, {'key': 'percent', 'label': 'Percent', 'n': True}],
                   'rows': score_rows, 'note': note}]
        if ctl:
            panels.append({'kicker': f'Recommended actions below their maximum points: {n(len(ctl))}',
                           'cols': [{'key': 'title', 'label': 'Recommended action'}, {'key': 'service', 'label': 'Service'},
                                    {'key': 'points', 'label': 'Points', 'n': True}, {'key': 'max', 'label': 'Maximum', 'n': True}],
                           'rows': [{'title': {'text': self.D(c['title'])}, 'service': {'mono': self.D(c.get('service') or '')},
                                     'points': num(c['controlScore.score']), 'max': num(c['maxScore'])} for c in ctl],
                           'note': f'{esc(scope)}. Sorted by points not earned. Deprecated actions are left out.'})
        self.add({'type': 'panels', 'kicker': 'Microsoft Secure Score', 'title': 'Secure Score and its recommended actions',
                  'cols': 1, 'panels': panels}, 'secure-score')
        return shown, ctl

    def footer(self, method, definitions, not_counted):
        self.add({'type': 'footer', 'cells': [
            {'h': 'Method', 'body': method}, {'h': 'Definitions', 'body': definitions}, {'h': 'Not counted', 'body': not_counted}],
            'sig': f'{self.tenant} · {self.as_of}',
            'disclaimer': f'Point-in-time data as of {self.as_of}; not an audit, attestation or certification. '
                          f'Report edition {self.recipe} {self.version}.'}, 'footer')

    # ------------------------------------------------------------ write
    def write(self):
        self.FACTS['_strings'] = {'value': sorted(self.STRINGS), 'source': 'data and Microsoft vocabulary'}
        omit = set(self.run.get('omit', []))
        unknown = omit - {sec.get('id') for sec in self.S}
        if unknown:
            sys.exit(f'run.json omit names sections this report does not have: {sorted(unknown)}')
        kept = [sec for sec in self.S if sec.get('id') not in omit]
        doc = {'schemaVersion': '2.0.0', 'deckType': self.recipe, 'tenantSlug': self.run['tenantSlug'],
               'tenantName': self.tenant_raw, 'render': 'report', 'asOf': self.as_of, 'sample': False, 'sections': kept}
        manifest = {'schemaVersion': '1.0.0',
                    'tenant': {'name': self.tenant_raw, 'tenantId': self.run['tenantId'], 'slug': self.run['tenantSlug']},
                    'deck': {'type': self.recipe, 'title': self.title, 'skill': f'inspect365-report-recipes {self.recipe} v{self.version}',
                             'render': 'report', 'template': 'report-template.html'},
                    'generation': {'generatedAt': f'{self.as_of}T00:00:00Z', 'recipe': self.recipe, 'recipeVersion': self.version,
                                   'queries': len(self.spec['queries']), 'inputsSha256': self.digest, 'model': None, 'factsOnly': True},
                    'sections': [sec['id'] for sec in self.S if sec.get('id')],
                    'mcp': {'environment': self.run.get('environment'),
                            'entitiesUsed': sorted({q.get('entity', 'finding-definitions') for q in self.spec['queries']})}}
        json.dump(doc, open(self.run_dir / 'data-rendered.json', 'w'), indent=1, ensure_ascii=False)
        json.dump(manifest, open(self.run_dir / 'manifest.json', 'w'), indent=1, ensure_ascii=False)
        json.dump(self.FACTS, open(self.run_dir / 'facts.json', 'w'), indent=1, ensure_ascii=False, sort_keys=True, default=str)
        print(f'wrote {self.run_dir.name}: {len(self.S)} sections, {len(self.FACTS)} facts')
