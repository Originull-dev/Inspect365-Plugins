# Release notes

All three plugins share a version number, and every release carries all three.

## 0.8.6 (2026-11-25, preview)

- Each report is now a skill of its own: tenant overview, users and groups, devices, Entra apps, app access, installed software, and mailboxes with Teams and SharePoint. Ask for a report by name and the matching skill builds it. The reports themselves are unchanged.
- A new report, SharePoint permissions: who can open each SharePoint site and each document library, Teams sites included, with every group expanded to its people. It shows which libraries and subsites have unique permissions, what is open to everyone in the organization, and groups that hold a level with no one in them. It comes in two styles from the same data, a flat report to read or print and an explorer to look things up, and it asks which you want. It also asks whether the report is for your own team or for your client: the client's copy carries no Inspect 365 name or link.
- The SharePoint permissions report needs the tenant's SharePoint permissions in Inspect 365, which Inspect 365 collects once the tenant consents to **Sites.FullControl.All** under **SharePoint Online**. Until they are collected, the skill says so and stops.
- The plugin's self-test is a skill of its own. Asking "Test the Inspect 365 plugin." still runs it.
- Each skill now says where its scripts are, in the way each app expects.
- If you ask for a report or the self-test without naming a tenant, the plugin asks which tenant to use instead of picking one.
- The devices report no longer says every device reports Encrypted when a tenant has no active corporate devices.
- On a wide screen, a report's headline figures fit on one row.

## 0.6.3 (2026-11-05, preview)

The first public release, for Copilot Cowork, Claude and ChatGPT.

- The Inspect 365 connector and the reports skill with seven fact reports: tenant overview, users and groups, devices, Entra apps, app access, installed software, and mailboxes with Teams and SharePoint.
- The Entra apps report opens with a diagram of the data each app can reach.
- Asking "Test the Inspect 365 plugin." runs the plugin's self-test, which checks the installed files, the scripts and the connector.
