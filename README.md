# Inspect 365 plugins

Plugins that connect Microsoft 365 Copilot Cowork, Claude and ChatGPT to [Inspect 365](https://inspect365.app). These are preview releases: each package passes our build checks, and testing in each app is under way.

## Who they're for

MSPs and IT teams that use Inspect 365 to look after the Microsoft 365 tenants they manage. Every plugin needs an Inspect 365 account, and you sign in with the work account you use for Inspect 365.

## What a plugin does

Each plugin carries the same parts, packaged for its app:

- **The Inspect 365 connector**, a remote MCP server. Ask about a client's findings and the decisions made on them, its users, devices, apps, policies and Microsoft Secure Score, or compare tenants. The connector answers from the data Inspect 365 has collected from Entra, Intune, Defender and other Microsoft 365 services.
- **Seven fact report skills**, one per report: tenant overview, users and groups, devices, Entra apps, app access, installed software, and mailboxes with Teams and SharePoint. Each builds its report for one tenant as an HTML page from fixed queries and scripts, so the same data always gives the same report.
- **The SharePoint permissions report skill**, which reports who can open each SharePoint site and each document library for one tenant, Teams sites included, with every group expanded to its people. It comes as a flat report or as an explorer, and asks which you want and whether it is for your own team or for your client. It needs SharePoint permissions in your Inspect 365 data.
- **A test skill**, which checks the plugin where it is installed: its files and scripts, the connector, and one report from start to finish.

## What's in this repository

| Folder | App | Contents |
|---|---|---|
| [`copilot-cowork/`](copilot-cowork) | Microsoft 365 Copilot Cowork | The Microsoft 365 app package: manifest, tool list, icons and the skills |
| [`claude/`](claude) | Claude apps and Claude Code | The Claude plugin: plugin manifest, connector, icons and the skills |
| [`chatgpt/`](chatgpt) | ChatGPT and Codex | The plugin in OpenAI's plugin format: manifest, connector, icon and the skills |

The skills are the same in all three folders. Each folder's README covers what that package contains and how to install it.

`.claude-plugin/marketplace.json` lists the Claude plugin and `.agents/plugins/marketplace.json` lists the ChatGPT plugin, so Claude, Claude Code and Codex can add this repository as a plugin source. [RELEASE-NOTES.md](RELEASE-NOTES.md) lists the changes in each version.

## Download

Each [release](https://github.com/Originull-dev/Inspect365-Plugins/releases) carries one zip per app. These links always give the latest one:

- Copilot Cowork: [inspect365-copilot-cowork.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-copilot-cowork.zip)
- Claude: [inspect365-claude.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-claude.zip)
- ChatGPT: [inspect365-chatgpt.zip](https://github.com/Originull-dev/Inspect365-Plugins/releases/latest/download/inspect365-chatgpt.zip)

## Data and privacy

The connector talks to one server, `https://us-mcp.inspect365.app/mcp`, over HTTPS, and signs you in with OAuth. It shows only the tenants your Inspect 365 account can see. The skills' scripts use Python's standard library and make no network calls: they save the connector's answers and write each report into a folder on the computer or sandbox where your AI app runs. Inspect 365's [privacy policy](https://inspect365.app/privacy) and [terms](https://inspect365.app/terms) apply.

## License

Proprietary. You may install and use these plugins with an Inspect 365 account. See [LICENSE](LICENSE).
