# Issue tracker: GitHub

Issues and specs for this plugin live as GitHub issues in this repository. Use the
`gh` CLI for all operations; it infers the repository from `git remote -v`.

This file is shared by every LogSquirl plugin and managed by LogSquirl-Plugin-CI
(`scripts/sync-plugin.sh`): change it there, not here.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body-file <file> --milestone <release>`.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open --milestone <release>`.
- **Comment, label, close**: `gh issue comment`, `gh issue edit --add-label` / `--remove-label`,
  `gh issue close <number> --comment "..."`.
- **Blocking**: GitHub's native issue dependencies,
  `gh api --method POST repos/<owner>/<repo>/issues/<n>/dependencies/blocked_by -F issue_id=<blocker database id>`
  (`gh api repos/<owner>/<repo>/issues/<blocker> --jq .id`). A blocker may be an issue in
  another repository, such as a LogSquirl host issue whose plugin API the ticket needs.

## Labels

Labels say what kind of ticket it is and where it stands in triage, never which release it
is planned for: `bug`, `enhancement`, `documentation`, and the triage states
`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`.

## Release planning: milestones

Which release a ticket is planned for is its **milestone**, as in LogSquirl itself.

- **One milestone per planned release**, named like the release tag without the `v`:
  `0.4.0`, `0.5.0`, …
- **Every ticket gets a milestone when it is filed**: the release it is planned for. Whoever
  files it, maintainer or agent, sets it; if the milestone of the next release does not exist
  yet, create it (`gh api repos/<owner>/<repo>/milestones -f title=<release>`).
- **No milestone means backlog**: wanted, but deliberately not planned for a release. There
  is no "Later" milestone.
- **Only the maintainer moves a ticket to another milestone or removes it.**
- **Among `ready-for-agent` tickets, those in the nearest open milestone come first.**
- **A plugin that needs a LogSquirl release** (a new plugin API function) is planned for a
  plugin milestone after that LogSquirl release; its ticket is blocked by the host issue.
- **At release** the maintainer closes the milestone. Anything still open is moved to the
  next milestone or back to the backlog, deliberately.
