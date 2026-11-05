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

In claude.ai or the Claude desktop app, go to Customize > Plugins and add it one of two ways:

- Select Add > Add marketplace, enter `Originull-dev/Inspect365-Plugins` and add Inspect 365. Turn on Sync automatically for the marketplace to get new versions.
- Download [inspect365-claude.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-claude.zip), select Add > Upload plugin and choose the zip.

Then open the plugin's Connectors tab, connect Inspect 365 and sign in. On a Team or Enterprise plan, an Owner adds the connector for the organization first. The reports need Code execution and file creation turned on, under Settings > Capabilities.

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
