# CLAUDE.md

Report-only update checker for three Ubuntu Server machines ("optiplex",
"pihole", "droplet"). It emails one HTML report per run via the Resend HTTPS API.
See README.md for how it's used.

## Workflow (standing instruction from the repo owner)

After making changes, without asking first:

1. Run the checks below. If any fail, fix them, or stop and report. Never
   merge failing work.
2. Commit, push to the working branch, open a pull request into `main` and
   merge it.
3. If the previous PR from the working branch has already been merged, restart
   the branch from the latest `main` before committing. Don't stack new
   commits on already-merged history.

Tell the owner what changed and give the PR link.

## Checks before every merge

```bash
python3 -m unittest discover -s tests       # all tests must pass
shellcheck install.sh uninstall.sh          # must be clean
python3 update_checker.py --no-email --skip-apt-update --config examples/optiplex.conf --secrets /nonexistent
```

Test `install.sh` / `uninstall.sh` changes with a stub `systemctl` on the
PATH when the environment has no systemd.

## Rules for the code

- **Report only.** Never install, upgrade, restart or remove anything on the
  machine. The only state-changing command allowed is `apt-get update`.
  Programs are only ever run with a command that prints their version. Never
  guess arguments that might start a daemon: the generic guess is
  `--version` only, and `KNOWN_APPS` entries use verified version commands.
- **Python 3 standard library only.** No pip packages. One script,
  `update_checker.py`, installed as `/usr/local/sbin/update-checker`.
- **A failing check must not stop the run.** Raise from a check and
  `run_checks` turns it into an error section, or record per-item errors in
  the check's own table.
- **Every run emails the report**, scheduled or started by a command
  (`--dry-run` prints and emails). `--no-email` is the only print-only mode.
  `send_when_up_to_date` (default yes) is the only other way to skip an email.
- Per-machine behaviour lives in `/etc/update-checker/config` (INI). Keep
  `config/config.example` and `examples/*.conf` in sync with new options, and
  make new options default sensibly so existing configs keep working.
  `install.sh` never overwrites an existing config. If an upgrade needs a
  config change, prompt for it the way `send_when_up_to_date` is migrated.
- **Secrets:** the Resend key and optional GitHub token live only in
  `/etc/update-checker/secret.env` (root, 600) on each machine. Never commit
  real keys, print them, or send them anywhere except their own API.
- Update README.md for any user-visible change. Add tests in
  `tests/test_update_checker.py`, mocking `run`/`http`/`Registry` instead of
  calling real services.

## Environment notes (cloud sessions)

- The GitHub API (`api.github.com`), lscr.io, quay.io and the Tailscale and
  Cloudflare apt repos may be blocked. Docker Hub, ghcr.io and
  registry.gitlab.com have worked. Cover blocked lookups with mocked tests and
  say so.
- The container is Ubuntu 24.04 running as root without systemd or a Docker
  daemon. The apt, reboot, disk and apps checks can be run for real.
