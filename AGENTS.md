# Agent Guidelines

## Git & Branching Rules

- Work on the branch that is currently checked out; do not create branches unless I ask. Start every task with a clean git status; if it is not clean, stop and tell me.
- Do not commit. Leave all changes in the working tree and report with `git diff --stat`; I review and commit myself.
- Never push, reset --hard, clean, checkout ., rebase or amend. I push and roll back myself.
- Before engine, guard or signing changes, remind me to tag a checkpoint.
- Run `flutter analyze`, `flutter test` (default concurrency) and the cargo checks before reporting, and show the real output.
