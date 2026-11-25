---
name: inspect365-app-access-report
description: Build the Inspect 365 app access report for one tenant from fixed queries and scripts, so the same data always gives the same report. It lists every app outside Microsoft's own that holds a permission or a directory role, by the data each permission reaches (mail, files, Teams, directory data, access control and more) and how the app was given it, with a diagram from apps to data. Use when the user asks which apps can reach mail, files or other data, what third-party apps can access in a client's tenant, or for an app access report.
license: Proprietary
metadata:
  author: Inspect 365
  version: "0.8.6"
---


# App access report

This skill builds one Inspect 365 report for one tenant, the app access report. It covers: every app outside Microsoft's own that holds a permission or a directory role, by the data each permission reaches (mail, files, Teams, directory data, access control and more) and how the app was given it, with a diagram from apps to data.

The report states facts only. The scripts in this skill compute every number from the Inspect 365 tool results you save, and write the report. You run the calls and the scripts. You don't write report text, summarize findings, order them by importance or add advice.

The report page is light and carries no Inspect 365 name, logo or colors, so it can go to the user's client under the user's own brand.

Unlike the other Inspect 365 reports, it has no opening section of finding checks and Microsoft Secure Score. All scripts are in this skill's `scripts` folder and use only the Python standard library. The commands below give each script's path from this skill's folder, the folder that holds this file. If your working folder is somewhere else, put the skill folder's full path in front of `scripts/`.

## Steps

1. **Pick the tenant.** Call the Inspect 365 tool `list_available_tenants`. If the user didn't name a tenant, ask which tenant to run the report for and wait for the answer; you may offer tenants from the list as choices, but don't pick one yourself, even if only one is listed or one was used earlier. A tenant whose name matches what the user named exactly is the one; if no name matches exactly and more than one matches in part, ask which one. Note its `tenantId` (not its `id`) and its name.

2. **Plan the run.**
   ```
   python3 scripts/report.py plan app-access --tenant-id <tenant-id> --tenant-name "<tenant name>" --out <folder>
   ```
   For `--out`, give a folder you can write to, such as your working folder, and create it if it doesn't exist. This skill's own folder can be read-only, and the script won't write there. The report is dated today in UTC, because Inspect 365 serves the tenant's current data. If the user asks for an earlier date, tell them the report can only show today's data; don't pass a date. The script creates a new run folder in `--out`, prints its path, and prints one line per call: a call ID, the Inspect 365 tool, and the exact arguments. Plan once per report: a second plan starts another empty run folder. The run folder's `run.json` records the tenant, the date, the plugin version (`plugin`) and `environment`, the Inspect 365 server this plugin reads: `us-production` in the package customers install, `dev` in Inspect 365's own test package. The environment doesn't change what the report says.

3. **Run every call and save it.** For each line the plan printed:
   - Call that Inspect 365 tool with exactly the printed arguments. Don't add, remove or change any argument. `filters` is a string that holds a JSON array: pass that string as printed, not the array inside it. `fields` is a list: pass it as a list. The page sizes (`maxResults`) differ from call to call as planned; pass each as printed.
   - Write the tool's result text, exactly as returned, to `<run folder>/raw/<call ID>.json`. Don't reformat, shorten, correct or summarize it. The text is JSON, sometimes wrapped as `{"result": "<JSON text>"}`; `save` takes either, so there's no need to try a call first to see its format.
   - Run `python3 scripts/report.py save <run folder> <call ID>`.

   Make only the planned calls. If you can call the Inspect 365 tools from a script, you may make them from `<run folder>/calls.json`, which holds the same calls as a JSON list of objects with `id`, `tool` and `arguments`, the arguments exactly as printed. Write what the script gets back: the text if it's a string, `json.dumps` of it if it's data. `save` reads the data, not its layout, so either is fine and there's no need to check which you got. Treat an exception, an error flag on the result, or a result that isn't JSON (Inspect 365 reports an error as a plain sentence) as a failed call; there's no need to find out which flag your script tool uses, because `save` refuses anything that isn't the tool's JSON for that call. Retry a failed call once; if it fails again, stop the script and tell the user which call ID failed. `save` refuses a result that isn't the tool's JSON, so an error written to a file by mistake stops there. A script may follow `nextPageToken` itself, writing the pages to the same file names.

   **Long lists come in pages.** When a result holds a `nextPageToken`, `save` says so. The token is in the result's JSON: inside the `"result"` text when the result is wrapped, at the top level when it isn't. Call the same tool again with the same arguments plus `pageToken` set to that value, exactly as returned, and write that result to `raw/<call ID>.2.json`, the next one to `raw/<call ID>.3.json`, and so on. Run `save` after each page, or once after the last page when a script fetched them all; either way it joins the pages once the last one is in, and when every page is already in `raw/` it joins them without a notice. The token's form can change from one page to the next; pass each one as returned.

   If `save` reports an echo mismatch, the call didn't match the plan. Run it again exactly as printed and save it again. `python3 scripts/report.py status <run folder>` lists the calls still missing; `build` checks that every call and page is in by itself, so running `status` first is optional. Read everything `save`, `status` and `build` print, and don't cut their output short: a page notice or a note can come before the last lines.

4. **Brand it, only if the user asks.** If the user gives their company name, a tagline, a logo file, a header color, an accent color or a footer line, write `<run folder>/brand.json` with only the fields they gave:
   ```json
   {"name": "Their Company", "tagline": "IT and security", "logo": "logo.png",
    "headerBackground": "#12304f", "accent": "#e0a526", "footer": "Confidential."}
   ```
   Copy the logo file into the run folder under the name you put in `logo` (PNG, JPEG, GIF, WebP or SVG, under 512 KB). Colors are hex values. Don't choose colors, write a tagline or add a footer the user didn't give. With no `brand.json` the report has no branding at all.

5. **Build.**
   ```
   python3 scripts/report.py build <run folder>
   ```
   It computes the facts, writes `report.html` in the run folder, and checks that every number in the report is a recorded fact. It stops with a message if anything is missing or fails a check.

6. **Hand over the file.** Give the user `report.html`, copied under the run folder's name if you put it in their output folder, such as `inspect365-app-access-contoso-2026-10-19.html`. Tell them the report's name, the plugin version (the `plugin` field in `run.json`; the report has no version of its own), the tenant, the as-of date, and every line the build printed, word for word, from the first line to the last one, which starts with `report:` and gives the file's path. A line that starts with `note:` is information: pass it on and take no other action. Give the build's lines only; repeat what `save` or `status` printed only if one of them reported a problem. If `environment` in `run.json` is `dev`, say that the data came from Inspect 365's test server. Don't describe or interpret the findings in the same message. If the user asks what the data means, answer separately and say that the answer isn't part of the report.

## When something fails

- **The build says a list holds fewer rows than its total:** a page is missing. Fetch it as in step 3 and build again.
- **A tool call fails or times out:** retry it once. If it fails again, stop and tell the user which call ID failed.
- **A call or script comes back as not executed** (for example "NOT EXECUTED" after a session disconnect): it never ran, so nothing was saved. Run it again; this doesn't count as the one retry.
- **The build stops on a value it doesn't know** (a new status or label in the tenant's data): tell the user the message; don't edit the scripts.
- **The build stops with a Python error** (a traceback, or a line such as `TypeError: ...`): it's a bug in this skill's scripts, not something to fix in the data. Tell the user the last lines it printed, and don't edit the scripts or the saved results.
- **The check fails:** don't edit the report or the saved results. Tell the user the build failed and show the script's message.
- **`brand.json` is rejected:** the message names the field. Fix that field from what the user gave, or remove it, and build again.

## Other Inspect 365 reports

This skill builds only the app access report. Each other report is a skill of its own, built the same way. If the user asks for one of these, use that skill:

- `inspect365-tenant-overview-report`: the tenant overview (findings by area, Microsoft Secure Score, high-impact users and devices, object counts)
- `inspect365-users-and-groups-report`: users and groups (accounts, sign-in, licenses, directory roles, sign-in methods, guests, groups and Conditional Access)
- `inspect365-devices-report`: devices (coverage across Entra, Intune and Defender, compliance, encryption, antivirus, Windows, Autopilot and an inventory)
- `inspect365-entra-apps-report`: Entra apps (service principals by publisher, roles and permissions, credentials, consent and sign-in activity)
- `inspect365-installed-software-report`: installed software (inventory, vulnerabilities, exploits and end of support)
- `inspect365-mailboxes-teams-sharepoint-report`: mailboxes, Teams and SharePoint (mailboxes, forwarding and access, teams and channels, SharePoint sites and OneDrive)
- `inspect365-sharepoint-permissions-report`: who can open each SharePoint site and document library, as a flat report or an explorer
