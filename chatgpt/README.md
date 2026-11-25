# Inspect 365 for ChatGPT

Connects ChatGPT to [Inspect 365](https://inspect365.app), so you can ask about the Microsoft 365 tenants you manage and build fact reports for one tenant. For MSPs and IT teams with an Inspect 365 account. This is a preview release.

## What it contains

- `plugin.json`: the plugin's name, version and the listing text ChatGPT shows, in OpenAI's plugin format.
- `mcp.json`: the Inspect 365 connector, a remote MCP server at `https://us-mcp.inspect365.app/mcp`. ChatGPT registers itself with Inspect 365's sign-in service, and you sign in with the work account you use for Inspect 365.
- `skills/`: nine skills. Seven build one fact report each (`inspect365-tenant-overview-report`, `inspect365-users-and-groups-report`, `inspect365-devices-report`, `inspect365-entra-apps-report`, `inspect365-app-access-report`, `inspect365-installed-software-report`, `inspect365-mailboxes-teams-sharepoint-report`): `SKILL.md` tells ChatGPT how to plan the report's queries, run them through the connector and build the report with the Python scripts in `scripts/`.
- `skills/inspect365-sharepoint-permissions-report/`: who can open each SharePoint site and each document library, Teams sites included, as a flat report or as an explorer. It asks which style you want and whether it is for your own team or for your client; the client's copy carries no Inspect 365 name or link. It needs SharePoint permissions in your Inspect 365 data.
- `skills/inspect365-plugin-test/`: the plugin's self-test. Ask ChatGPT to test the Inspect 365 plugin.
- `assets/icon.png`: the plugin's icon.

## What it runs, sends and fetches

- ChatGPT calls the connector's tools to read your Inspect 365 data: findings and the decisions made on them, users, devices, apps, policies and Microsoft Secure Score. The connector answers from data Inspect 365 has already collected and shows only the tenants your account can see.
- The skill's scripts run on Python 3's standard library. They make no network calls and install nothing. They write the query plan, the connector's answers and `report.html` into a run folder where ChatGPT runs them.
- The plugin sends and fetches nothing else.

## Install

ChatGPT runs plugins in Work mode in the ChatGPT desktop app. Until Inspect 365 is in ChatGPT's plugin directory, you add it from a marketplace.

With the Codex command line, add this repository as a marketplace and restart the ChatGPT desktop app:

```
codex plugin marketplace add Originull-dev/Inspect365-Plugins
```

Without it, download [inspect365-chatgpt.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-chatgpt.zip), unzip it to `~/plugins/inspect365`, save the marketplace file below as `~/.agents/plugins/marketplace.json`, and restart the app:

```json
{
  "name": "inspect365",
  "interface": {"displayName": "Inspect 365"},
  "plugins": [
    {
      "name": "inspect365",
      "source": {"source": "local", "path": "./plugins/inspect365"},
      "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
      "category": "Productivity"
    }
  ]
}
```

Then open the Plugins Directory, choose the Inspect 365 marketplace, install Inspect 365 and sign in. In a Work conversation, type `@` and choose Inspect 365.

## Try it

- Test the Inspect 365 plugin.
- Build the tenant overview report for one of my clients.
- Which apps outside Microsoft can read mail or files for this client?

## License

Proprietary. See [LICENSE](LICENSE).
