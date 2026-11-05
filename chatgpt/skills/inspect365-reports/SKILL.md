---
name: inspect365-reports
description: Build an Inspect 365 fact report for one tenant from fixed queries and scripts, so the same data always gives the same report. The reports are the tenant overview; users and groups (with Conditional Access and licenses); devices; Entra apps; app access (what each app can reach); installed software; mailboxes, Teams and SharePoint. Use when the user asks for a tenant overview, a users and groups report, an identity report, a license report, a devices report, an Entra apps or app permissions report, an app access report or which apps can reach mail, files or other data, an installed software or vulnerability report, a mailbox, Teams or SharePoint report, or says build the Inspect 365 report for a client. Also use when the user asks to test, check or validate the Inspect 365 plugin, its reports or this skill.
license: Proprietary
metadata:
  author: Inspect 365
  version: "0.6.3"
---

# Inspect 365 fact reports

These reports state facts only. The scripts in this skill compute every number from the Inspect 365 tool results you save, and write the report. You run the calls and the scripts. You don't write report text, summarize findings, order them by importance or add advice.

The report page is light and carries no Inspect 365 name, logo or colors, so it can go to the user's client under the user's own brand.

| Recipe | What it covers |
|---|---|
| `tenant-overview` | Findings by area, Microsoft Secure Score with its recommended actions by category, high-impact users and devices, object counts |
| `users-and-groups` | Accounts, sign-in, licenses purchased, assigned and available, directory roles, sign-in methods, guests and pending invitations, groups and Conditional Access |
| `devices` | Device records, coverage across Entra, Intune and Defender, exposure, antivirus, compliance and the settings that failed, encryption, firewall, Windows, Autopilot and a device inventory |
| `entra-apps` | Service principals by publisher, roles and permissions, apps that can read company content, credentials, consent and sign-in activity |
| `app-access` | Every app outside Microsoft's own that holds a permission or a directory role, by the data each permission reaches (mail, files, Teams, directory data, access control and more) and how the app was given it, with a diagram from apps to data |
| `installed-software` | Software inventory, vulnerabilities, exploits and end of support |
| `mailboxes-teams-sharepoint` | Mailboxes, forwarding and access, teams and channels, SharePoint sites and OneDrive accounts |

Every report except `app-access` opens with the finding checks for its area and Microsoft Secure Score. All scripts are in this skill's `scripts` folder and use only the Python standard library.

## Steps

1. **Pick the tenant.** Call the Inspect 365 tool `list_available_tenants`. If more than one tenant matches what the user named, ask which one. Note its tenant ID and name.

2. **Plan the run.**
   ```
   python3 scripts/report.py plan <recipe> --tenant-id <tenant-id> --tenant-name "<tenant name>" --out <folder>
   ```
   For `--out`, give a folder you can write to, such as your working folder. This skill's own folder can be read-only, and the script won't write there. The report is dated today in UTC, because Inspect 365 serves the tenant's current data. If the user asks for an earlier date, tell them the report can only show today's data; don't pass a date. The script creates a new run folder in `--out`, prints its path, and prints one line per call: a call ID, the Inspect 365 tool, and the exact arguments. Plan once per report: a second plan starts another empty run folder.

3. **Run every call and save it.** For each line the plan printed:
   - Call that Inspect 365 tool with exactly the printed arguments. Don't add, remove or change any argument. `filters` is a string that holds a JSON array: pass that string as printed, not the array inside it. `fields` is a list: pass it as a list.
   - Write the tool's result text, exactly as returned, to `<run folder>/raw/<call ID>.json`. Don't reformat, shorten, correct or summarize it. The text is JSON, sometimes wrapped as `{"result": "<JSON text>"}`; `save` takes either, so there's no need to try a call first to see its format.
   - Run `python3 scripts/report.py save <run folder> <call ID>`.

   Make only the planned calls. If you can call the Inspect 365 tools from a script, you may make them from `<run folder>/calls.json`, which holds the same calls as a JSON list of objects with `id`, `tool` and `arguments`, the arguments exactly as printed. Write each result's text exactly as returned. If the script gets a result as data rather than text, write it with `json.dumps`: `save` reads the data, not its spacing, and checks it the same way. A script may follow `nextPageToken` itself, writing the pages to the same file names.

   **Long lists come in pages.** When a result holds a `nextPageToken`, `save` says so. Call the same tool again with the same arguments plus `pageToken` set to that value, exactly as returned, and write that result to `raw/<call ID>.2.json`, the next one to `raw/<call ID>.3.json`, and so on. Run `save` again after each page; it joins the pages once the last one is in. The token's form can change from one page to the next; pass each one as returned.

   If `save` reports an echo mismatch, the call didn't match the plan. Run it again exactly as printed and save it again. `python3 scripts/report.py status <run folder>` lists the calls still missing.

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

6. **Hand over the file.** Give the user `report.html`, copied under the run folder's name if you put it in their output folder, such as `inspect365-devices-contoso-2026-10-19.html`. Tell them the recipe and version, the tenant, the as-of date and the line the build printed. Don't describe or interpret the findings in the same message. If the user asks what the data means, answer separately and say that the answer isn't part of the report.

## When something fails

- **The build says a list holds fewer rows than its total:** a page is missing. Fetch it as in step 3 and build again.
- **A tool call fails or times out:** retry it once. If it fails again, stop and tell the user which call ID failed.
- **The build stops on a value it doesn't know** (a new status or label in the tenant's data): tell the user the message; don't edit the scripts.
- **The build stops with a Python error** (a traceback, or a line such as `TypeError: ...`): it's a bug in this skill's scripts, not something to fix in the data. Tell the user the last lines it printed, and don't edit the scripts or the saved results.
- **The check fails:** don't edit the report or the saved results. Tell the user the build failed and show the script's message.
- **`brand.json` is rejected:** the message names the field. Fix that field from what the user gave, or remove it, and build again.

## Test the plugin

When the user asks to test, check or validate the Inspect 365 plugin, its reports or this skill:

1. Run `python3 scripts/selftest.py offline --out <folder>`, with a folder you can write to for `--out`. A `NOTE` line is information, not a failure.
2. Pick the tenant as in step 1 of the Steps above.
3. Run `python3 scripts/selftest.py plan --tenant-id <tenant-id> --tenant-name "<tenant name>" --out <folder>`. Make each printed call exactly as printed, as in step 3 of the Steps above, and write each result, exactly as returned, to `<run folder>/raw/<call ID>.json`. If `enabled_users_page` returns a `nextPageToken`, call it once more with the same arguments plus `pageToken` set to that value, write that result to `raw/enabled_users_page.2.json`, and fetch no further pages.
4. Run `python3 scripts/selftest.py check <run folder>`. It runs the same checks as `save`, so don't run `report.py save` on these results.
5. Build the `devices` report for the same tenant by the Steps above.
6. Report every line the `offline` and `check` commands printed, exactly as printed, and the last line the devices build printed. Then list, separately, anything in these instructions that was unclear, any step you retried or worked around, and anything you did that the instructions didn't say. Don't edit a script or a saved result to make a check pass; report the failure instead.
