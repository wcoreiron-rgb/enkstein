# Token hygiene (RTK)

The `rtk hook claude` PreToolUse hook already rewrites `cat`, `grep`, `ls`, `find`,
`rg`, and `pytest` automatically (verified via `rtk hook check`) — no need to prefix
them with `rtk`. Two patterns the hook can NOT catch, so avoid them:

- **Don't page through files with `sed -n START,ENDp file`.** RTK has no `sed` filter,
  so it dumps raw. Use the Read tool (offset/limit) or `rtk read` instead.
- **Run tests as `pytest …` or `python -m pytest …`, not `.venv/bin/python -m pytest …`.**
  The explicit venv path bypasses the hook matcher. Activate the venv (put `.venv/bin`
  on `PATH`) or call `rtk pytest` explicitly.
