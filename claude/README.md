# Inspect 365 for Claude

Connects Claude to [Inspect 365](https://inspect365.app), so you can ask about the Microsoft 365 tenants you manage and build fact reports for one tenant. For MSPs and IT teams with an Inspect 365 account. This is a preview release.

## What it contains

- `.mcp.json`: the Inspect 365 connector, a remote MCP server at `https://us-mcp.inspect365.app/mcp`. You sign in with OAuth, using the work account you use for Inspect 365.
- `skills/inspect365-reports/`: the reports skill. `SKILL.md` tells Claude how to plan a report's queries, run them through the connector and build the report with the Python scripts in `scripts/`. Seven reports: tenant overview, users and groups, devices, Entra apps, app access, installed software, and mailboxes with Teams and SharePoint.
- `color.png` and `outline.png`: the plugin's icons.

## What it runs, sends and fetches

- Claude calls the connector's tools to read your Inspect 365 data: findings and the decisions made on them, users, devices, apps, policies and Microsoft Secure Score. The connector answers from data Inspect 365 has already collected and shows only the tenants your account can see.
- The skill's scripts run on Python 3's standard library. They make no network calls and install nothing. They write the query plan, the connector's answers and `report.html` into a run folder on the computer or sandbox where Claude runs.
- The plugin sends and fetches nothing else.

## Install

In the Claude apps:

1. Download [inspect365-claude.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-claude.zip).
2. Go to Customize > Plugins > Add > Upload plugin and choose the zip.
3. Open the plugin's Connectors tab, connect Inspect 365 and sign in.

An organization Owner can add it for everyone instead: Organization settings > Plugins & skills > Add > Upload a plugin, then set its default access, and add the connector under Organization settings > Connectors.

In Claude Code, add this repository as a marketplace, install the plugin, then run `/mcp` and sign in to Inspect 365:

```
claude plugin marketplace add Originull-dev/Inspect365-Plugins
claude plugin install inspect365@inspect365
```

## Try it

- Test the Inspect 365 plugin.
- Build the tenant overview report for one of my clients.
- Which apps outside Microsoft can read mail or files for this client?

## License

Proprietary. See [LICENSE](LICENSE).
