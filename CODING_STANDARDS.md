# Coding standards

These are judgement calls a reviewer checks against the diff. `scripts/format.sh --check` and CI cover formatting.

## Docs move with behaviour

- When a change alters what a module does, the branch also updates that module's section under *Architecture* in `docs/DEVELOPER_GUIDE.md` (§1–6). If the module has no section, the branch adds one.
- A change the user can see also updates `README.md`.
- Every user-visible change gets an entry under `## [Unreleased]` in `CHANGELOG.md`, filed under *Added*, *Changed* or *Fixed*. The entry is a **bold headline**, then prose, and ends with the ticket number, `(#N)`.

## One action, one name, one behaviour

- An action that the sidebar, the Packet panel, the tcpdump menu and notifications all offer has the same name in each of them and in the docs.
- It also has the same preconditions everywhere it appears. Where the host API can't disable a menu entry, the menu entry refuses with a notification in the cases where the button is disabled.

## Code

- Give each line count, size or colour mix a named constant (`kSummaryMaxLines`) instead of a bare literal.
- Comments are `///` Doxygen briefs that say what something is for and why. Match the comment density of the surrounding code.
- A change in behaviour comes with a Catch2 `SCENARIO` in `tests/` that uses the existing tags. Where the ticket names a limit (a short sidebar, no capture, no selection), the test exercises that limit.

## Commits

- The subject is one imperative sentence about what changes for the user, with no type prefix and no trailing period. Example: *Put the custom command first in the live capture form*.
