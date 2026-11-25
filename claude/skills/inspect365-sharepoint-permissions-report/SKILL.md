---
name: inspect365-sharepoint-permissions-report
description: Build the Inspect 365 SharePoint permissions report for one tenant. It lists who can open each SharePoint site and each document library, Teams-connected and channel sites included, with every group expanded to its people. It shows which libraries and subsites have unique permissions (broken inheritance), what is open to everyone in the organization, site owners, members and visitors, site admins, guests, and groups that hold a level with no one in them. It comes in two styles from the same data, a flat report or an explorer, and the user picks one. Use when the user asks for a SharePoint permissions report, who has access to SharePoint sites, document libraries or Teams files, a library permissions or access review, which libraries have broken inheritance or unique permissions, or what Everyone except external users can open. For counts of sites, storage and activity, use the inspect365-mailboxes-teams-sharepoint-report skill instead.
license: Proprietary
metadata:
  author: Inspect 365
  version: "0.8.6"
---

# SharePoint permissions report

This skill builds the SharePoint permissions report for one tenant: who can open each SharePoint site and each document library. It comes in two styles, built from the same data:

| Style | File | What it is |
|---|---|---|
| Report | `report.html` | A flat report: every SharePoint site on one page, grouped by what it is connected to (SharePoint only, a Microsoft 365 group that is not in Teams, Teams). For each site and for each document library with its own permissions it has one row per grant, with the group, its permission level, how many people it brings and who they are. Each group's people are listed once, at the end. Made to read from top to bottom, print or save as a PDF. |
| Explorer | `explorer.html` | The same access as one page to move through: a tree of sites, subsites and libraries, filters for unique permissions and for access by everyone in the organization, a search, and a page for each person. Made to look things up. |

The report states what the data holds. The scripts in this skill compute every row from the Inspect 365 tool results you save, and write the page. You run the calls and the scripts. You don't write report text, summarize, rank or add advice. All scripts are in this skill's `scripts` folder and use only the Python standard library. The commands below give each script's path from this skill's folder, the folder that holds this file. In Claude Code and Cowork that folder is `${CLAUDE_SKILL_DIR}` and your working folder is somewhere else, so run a script as `python3 "${CLAUDE_SKILL_DIR}/scripts/<name>.py"`.

What the report covers: access to sites, subsites and document libraries. It does not cover permissions on single folders or files, files shared directly with people, sharing links, or OneDrive. Both styles say so.

## Steps

1. **Pick the tenant.** Call the Inspect 365 tool `list_available_tenants`. If the user didn't name a tenant, ask which tenant to run the report for and wait for the answer; you may offer tenants from the list as choices, but don't pick one yourself, even if only one is listed or one was used earlier. A tenant whose name matches what the user named exactly is the one; if no name matches exactly and more than one matches in part, ask which one. Note its `tenantId` (not its `id`) and its name.

2. **Ask the user two things.** Before you plan, ask whichever of these the user hasn't already told you, every time; don't guess either answer from anything else. If their request already gives both, such as "the flat report, for my client", don't ask again. If you ask both at once and one answer covers both, take it for both:
   - **Which style.** The flat report, to read through, print or send (`--style report`), or the explorer, to look things up (`--style explorer`). Describe the two as in the table above so they can choose. If they say they want both, use `--style both`.
   - **Who will read it.** Their own team (the MSP): the report names Inspect 365 and adds a link from each site, group, team and person into the Inspect 365 app. Use `--audience msp`. Or their client: the report carries no Inspect 365 name and no link into the app, because the client can't sign in there. Use `--audience client`.

   A copy made for the MSP must not be sent to a client. If the user wants a copy for each, run the Steps twice.

3. **Plan the run.**
   ```
   python3 scripts/sharepoint_permissions.py plan --tenant-id <tenant-id> --tenant-name "<tenant name>" --style <report, explorer or both> --audience <msp or client> --out <folder>
   ```
   For `--out`, give a folder you can write to, such as your working folder, and create it if it doesn't exist. This skill's own folder can be read-only, and the script won't write there. The report shows the tenant's current data, dated today in UTC; there is no earlier date to ask for. The script creates a new run folder in `--out`, prints its path, and prints one line per call: a call ID, the Inspect 365 tool, and the exact arguments. Plan once per run: a second plan starts another empty run folder. The run folder's `run.json` records the tenant, the date, the style, the audience, the plugin version (`plugin`) and `environment`, the Inspect 365 server this plugin reads: `us-production` in the package customers install, `dev` in Inspect 365's own test package. The environment doesn't change who can open what; in the MSP's copy it sets which Inspect 365 app the links open.

4. **Run every call and save it.** For each line the plan printed:
   - Call that Inspect 365 tool with exactly the printed arguments. Don't add, remove or change any argument. `filters` is a string that holds a JSON array: pass that string as printed, not the array inside it. `fields` is a list: pass it as a list. The page sizes (`maxResults`) differ from call to call as planned; pass each as printed.
   - Write the tool's result text, exactly as returned, to `<run folder>/raw/<call ID>.json`. Don't reformat, shorten, correct or summarize it. The text is JSON, sometimes wrapped as `{"result": "<JSON text>"}`; `save` takes either.
   - Run `python3 scripts/sharepoint_permissions.py save <run folder> <call ID>`.

   **These results are large.** A tenant with a few hundred libraries returns several megabytes: one page of `grants` is about 75,000 characters, and `grants`, `securables`, `roleAssignments` and `levels` come in many pages. Don't retype a result. If your host saved a tool result to a file, copy that file to `raw/<call ID>.json` (page 2 to `raw/<call ID>.2.json`, and so on). If you can call the Inspect 365 tools from a script, make the calls from `<run folder>/calls.json`, which holds the same calls as a JSON list of objects with `id`, `tool` and `arguments`, and let the script follow `nextPageToken` and write each page. Write what the script gets back: the text if it's a string, `json.dumps` of it if it's data. `save` reads the data, not its layout, so either is fine and there's no need to check which you got. Treat an exception, an error flag on the result, or a result that isn't JSON (Inspect 365 reports an error as a plain sentence) as a failed call; there's no need to find out which flag your script tool uses, because `save` refuses anything that isn't the tool's JSON for that call. Retry a failed call once; if it fails again, stop the script and tell the user which call ID failed. `save` refuses a result that isn't the tool's JSON, so an error written to a file by mistake stops there.

   **Long lists come in pages.** When a result holds a `nextPageToken`, `save` says so. The token is in the result's JSON: inside the `"result"` text when the result is wrapped, at the top level when it isn't. Call the same tool again with the same arguments plus `pageToken` set to that value, exactly as returned, and write that result to `raw/<call ID>.2.json`, the next one to `raw/<call ID>.3.json`, and so on. Run `save` after each page, or once after the last page when a script fetched them all; either way it joins the pages once the last one is in, and when every page is already in `raw/` it joins them without a notice. The token's form can change from one page to the next; pass each one as returned. The call `latestRun` is the one exception: it reads only the newest collection run, so don't fetch more pages for it.

   Make only the planned calls. Both styles need all of them. If `save` reports an echo mismatch, the call didn't match the plan. Run it again exactly as printed and save it again. `python3 scripts/sharepoint_permissions.py status <run folder>` lists the calls still missing; `build` checks that every list is complete by itself, so running `status` first is optional. Read everything `save`, `status` and `build` print, and don't cut their output short: a page notice or a note can come before the last lines.

5. **Build.**
   ```
   python3 scripts/sharepoint_permissions.py build <run folder>
   ```
   It checks that every list is complete, joins each grant to its permission level, and writes the style the user picked into the run folder: `report.html`, `explorer.html`, or both. It stops with a message if anything is missing or fails a check.

6. **Hand over the file.** Give the user the page the build wrote, copied under the run folder's name if you put it in their output folder, such as `inspect365-sharepoint-permissions-contoso-2026-11-23-report.html` or `...-explorer.html`. Tell them the tenant, the style, who the copy is for, the plugin version (the `plugin` field in `run.json`), and every line the build printed, word for word, from the line that starts with `collection:` to the last line with the file's path. Give the build's lines only; repeat what `save` or `status` printed only if one of them reported a problem. If `environment` in `run.json` is `dev`, say that the data came from Inspect 365's test server. Don't describe or interpret the access in the same message. If the user asks what the data means, answer separately and say that the answer isn't part of the report. If they later want the other style for the same audience, plan again with that style; the saved results of one run aren't reused by another.

## When something fails

- **A tool says it doesn't know `sharepoint-securables`, `sharepoint-grants`, `sharepoint-permission-levels` or `collection-runs`:** this Inspect 365 server doesn't serve SharePoint permissions yet. Stop and tell the user; the report can't be built from it.
- **The build says no SharePoint permissions have been collected:** the tenant's collection hasn't read them. Tell the user the message.
- **The build's `collection:` line says the latest run did not read SharePoint permissions:** the report is built from an earlier run. Tell the user that line; each site in the report shows the date its permissions were read.
- **The build says a list holds fewer rows than its total, or the same record twice:** a page is missing or was saved twice. Fetch that call's pages again in order as in step 4 and build again.
- **A tool call fails or times out:** retry it once. If it fails again, stop and tell the user which call ID failed.
- **A call or script comes back as not executed** (for example "NOT EXECUTED" after a session disconnect): it never ran, so nothing was saved. Run it again; this doesn't count as the one retry.
- **The build stops with a Python error** (a traceback, or a line such as `TypeError: ...`): it's a bug in this skill's scripts, not something to fix in the data. Tell the user the last lines it printed, and don't edit the scripts or the saved results.
- **Any check fails:** don't edit the page or the saved results. Tell the user the build failed and show the script's message.
