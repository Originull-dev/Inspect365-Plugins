# Inspect 365 for Copilot Cowork

Connects Microsoft 365 Copilot Cowork to [Inspect 365](https://inspect365.app), so you can ask about the Microsoft 365 tenants you manage and build fact reports for one tenant. For MSPs and IT teams with an Inspect 365 account. This is a preview release.

## What it contains

This folder holds the Microsoft 365 app package, unzipped. The release zip holds the same files without this README.

- `manifest.json`: the app manifest (schema 1.29), with the Inspect 365 connector, a remote MCP server at `https://us-mcp.inspect365.app/mcp`, and the reports skill. You sign in with the work account you use for Inspect 365.
- `tools/inspect365-tools.json`: the connector's tool list, which Cowork reads to verify the connector.
- `skills/inspect365-reports/`: the reports skill. `SKILL.md` tells Copilot how to plan a report's queries, run them through the connector and build the report with the Python scripts in `scripts/`. Seven reports: tenant overview, users and groups, devices, Entra apps, app access, installed software, and mailboxes with Teams and SharePoint.
- `color.png` and `outline.png`: the app's icons.

## What it runs, sends and fetches

- Copilot calls the connector's tools to read your Inspect 365 data: findings and the decisions made on them, users, devices, apps, policies and Microsoft Secure Score. The connector answers from data Inspect 365 has already collected and shows only the tenants your account can see.
- The skill's scripts run on Python 3's standard library. They make no network calls and install nothing. They write the query plan, the connector's answers and `report.html` into a run folder in Cowork.
- The plugin sends and fetches nothing else.

## Requirements

- A Microsoft 365 Copilot license and access to Cowork, which an admin grants through a Copilot Credits spending policy that includes Cowork.
- An Inspect 365 account.

## Install

1. Download [inspect365-copilot-cowork.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-copilot-cowork.zip).
2. In Cowork, go to Customize > Plugins > Upload plugin and choose the zip.
3. Sign in to Inspect 365 when Cowork asks.

An admin can make it available to others from the Microsoft 365 admin center, under Agents > Tools > Plugins.

## Try it

- Test the Inspect 365 plugin.
- Build the tenant overview report for one of my clients.
- Which apps outside Microsoft can read mail or files for this client?

## License

Proprietary. See [LICENSE](../LICENSE).
