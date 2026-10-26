# update-checker

A lightweight, **report-only** update checker for Ubuntu Server. Every 3 days it
checks the machine and emails one HTML report through the
[Resend](https://resend.com) HTTPS API (no SMTP, so it works on DigitalOcean).

It **never installs, upgrades, restarts or removes anything**. The only command
it runs that changes state is `apt-get update`, which refreshes the package lists.

One codebase for every machine: a single Python 3 script (standard library only)
whose behaviour is set by `/etc/update-checker/config`.

| Check | What it reports |
|---|---|
| System packages | `apt-get update`, then upgradable packages, **security updates listed separately** |
| Reboot required | `/var/run/reboot-required` and the packages in `reboot-required.pkgs` |
| Snaps | `snap refresh --list` (skipped if snap isn't installed) |
| Ubuntu Pro | summary of `pro security-status` (skipped if pro isn't installed) |
| Unattended upgrades | installed? `APT::Periodic` settings, apt-daily timers, last run. Warns if off |
| Disk space | usage per mount point, warning at a threshold (default 80%); flags a data disk that isn't mounted |
| Pi-hole | core / FTL / web versions from `pihole -v` (skipped if Pi-hole isn't installed) |
| Docker | every running container: name, image, tag, latest version, status; plus `docker system df` reclaimable space |

If one check fails (a registry is down, a command errors) the report says so in
that section and the other checks still run.

Example subjects:

```
[optiplex] 12 updates (3 security), 2 containers outdated, reboot needed
[pihole] All up to date
```

---

## Contents

- [Install](#install) (optiplex, pihole, droplet)
- [Editing the config](#editing-the-config)
- [Docker: the image → release-source map](#docker-the-image--release-source-map)
- [Testing with --dry-run](#testing-with---dry-run)
- [Running a check manually](#running-a-check-manually)
- [Viewing logs](#viewing-logs)
- [Changing the schedule](#changing-the-schedule)
- [Uninstall](#uninstall)
- [Files](#files)

---

## Install

### Before you start (once)

1. In Resend, verify the domain you send from (default sender is
   `info@rossmackenzie.co.uk`, so `rossmackenzie.co.uk` must be verified).
2. Create an API key at <https://resend.com/api-keys> with **Sending access**.
   Keep it handy; the installer asks for it on each machine.
3. Optional: a GitHub personal access token (no scopes needed) to raise the
   GitHub API limit from 60 to 5000 requests/hour. Only useful if you map many
   containers to `github:` sources.

### On each machine

```bash
git clone https://github.com/bobchomp/ubuntuupdatechecker.git
cd ubuntuupdatechecker
sudo ./install.sh --machine optiplex   # or pihole, droplet
```

The installer:

1. installs the script as `/usr/local/sbin/update-checker`;
2. creates `/etc/update-checker/config` from `examples/<machine>.conf` and asks
   for the label, recipient and from address;
3. asks for the **Resend API key** (typing is hidden) and an optional GitHub
   token, and writes them to `/etc/update-checker/secret.env`
   (`root:root`, mode `600`). The key stays on that machine and is only ever
   sent to `api.resend.com` when a report is emailed. It is never written to
   the repo or printed;
4. installs and starts `update-checker.timer` (systemd, runs as root);
5. offers to do a dry run.

The first report is emailed a few minutes after install, then every 3 days.

Re-running `install.sh` (e.g. after a `git pull`) updates the script and the
systemd units but **keeps your existing config and API key**. To start the
config and key over: `sudo ./install.sh --reconfigure`.

#### optiplex (CasaOS + Docker, SSD + HDD)

```bash
sudo ./install.sh --machine optiplex
```

Watches `/` and `/mnt/storage` (it warns if `/mnt/storage` is ever not mounted).
After installing, run `sudo update-checker --dry-run --only docker` and add any
containers listed as "not checked" to the map. See
[the Docker section](#docker-the-image--release-source-map).

#### pihole (Pi-hole on Ubuntu, no Docker)

```bash
sudo ./install.sh --machine pihole
```

The Docker check is disabled, the Pi-hole check is on, and
`send_when_up_to_date = no` so you only get email when something needs doing.
Change that to `yes` if you'd like a "[pihole] All up to date" every 3 days as
proof it's alive.

#### droplet (DigitalOcean + Docker)

```bash
sudo ./install.sh --machine droplet
```

Email uses HTTPS (port 443), so DigitalOcean's SMTP block doesn't matter. Add
your containers to `[docker.images]` the same way as on optiplex.

---

## Editing the config

```bash
sudo nano /etc/update-checker/config
sudo update-checker --dry-run      # check the result
```

Changes take effect on the next run; nothing needs restarting.

```ini
[general]
label = optiplex                       # shown in the subject: [optiplex] ...
recipient = you@example.com            # comma-separate several addresses
from_address = info@rossmackenzie.co.uk
from_name = Update Checker
send_when_up_to_date = yes             # no = only email when something needs attention

[checks]                               # set any to "no" to turn it off
apt = yes
reboot = yes
snap = yes
pro = yes
unattended_upgrades = yes
disk = yes
pihole = no
docker = yes

[disk]
mount_points = /, /mnt/storage
warn_percent = 80

[docker]
floating_tags =                        # extra tags to treat as floating (digest-checked)
ignore_containers =                    # container names to leave out of the report
digest_check_unmapped = no

[docker.images]
ghcr.io/immich-app/immich-server = github:immich-app/immich
```

What counts as "up to date" (so the email can be skipped when
`send_when_up_to_date = no`): no package/snap/Pi-hole/container updates, no
reboot needed, no disk warnings, unattended-upgrades enabled, and no failed checks.

To change the Resend key or GitHub token later, either re-run
`sudo ./install.sh --reconfigure`, or edit the file directly:

```bash
sudo nano /etc/update-checker/secret.env   # RESEND_API_KEY=re_... / GITHUB_TOKEN=...
sudo chmod 600 /etc/update-checker/secret.env
```

---

## Docker: the image → release-source map

Every running container is listed with its name, image and tag. How it's
checked depends on the tag:

**Floating tags** (`latest`, `stable`, `release`, … any tag with no digits) are
checked automatically: the digest of the image the container is running is
compared with the registry's current digest for that tag. "newer image pushed"
means a `docker pull` + recreate would get you a newer image.

**Version-pinned tags** (`v3.1.0`, `4.10.8`, optionally with `@sha256:...`)
are compared with the latest release from a source you configure in
`[docker.images]`. Pinned containers whose image isn't in the map are listed as
**"not checked"**, and the report prints the exact line to add.

### Adding a container

1. Find the image name:

   ```bash
   sudo update-checker --dry-run --only docker
   # or
   docker ps --format '{{.Names}}\t{{.Image}}'
   ```

2. Add a line to `[docker.images]`: the image **without** its tag, `=`, and a source:

   ```ini
   [docker.images]
   ghcr.io/immich-app/immich-server = github:immich-app/immich
   registry.gitlab.com/crafty-controller/crafty-4 = gitlab:crafty-controller/crafty-4
   lscr.io/linuxserver/sonarr = registry
   postgres = digest
   ```

   Docker Hub images can be written short (`postgres`, `jellyfin/jellyfin`)
   or long (`docker.io/library/postgres`), both work.

3. Check it: `sudo update-checker --dry-run --only docker`

### Sources

| Source | Use when | Compares |
|---|---|---|
| `github:OWNER/REPO` | the project publishes GitHub releases | running tag vs latest non-prerelease release (`v3.1.0` vs `v3.2.0`, a leading `v` is ignored) |
| `gitlab:GROUP/PROJECT` | releases are on gitlab.com (e.g. Crafty). Self-hosted: `gitlab:git.example.com/group/project` | same, using GitLab's latest release |
| `registry` | no releases, but the registry has version tags (e.g. linuxserver images) | newest tag in the image's registry with the **same shape** as the running tag: `4.0.9.2244-ls257` is compared only with `#.#.#.#-ls#` tags, `1.2.3-alpine` only with `#.#.#-alpine`, so `-rc`/`-beta` tags are ignored |
| `registry:OTHER/IMAGE` | as above, but read another image's tags | |
| `digest` | the tag moves even though it has digits (`postgres:16-alpine`, `valkey:8-bookworm`) | running digest vs the registry's digest for that tag |

If a mapped container runs a floating tag, the version from the image's
`org.opencontainers.image.version` label is used if present; otherwise it falls
back to a digest check and shows the latest release for reference.

Registries supported: Docker Hub, ghcr.io, lscr.io, registry.gitlab.com,
quay.io and any standard v2 registry. Public images need no login; for private
images, credentials saved by `sudo docker login` (in `/root/.docker/config.json`)
are used. Credential helpers/`credsStore` aren't supported.

`docker system df` output is included at the end of the section so you can see
how much space `docker system prune` could free (the script never prunes).

---

## Testing with --dry-run

```bash
sudo update-checker --dry-run
```

Runs every enabled check (including `apt-get update`) and prints the report to
the terminal instead of emailing it. Useful options:

```bash
sudo update-checker --dry-run --only docker              # just one or more checks
sudo update-checker --dry-run --only apt,reboot,disk
sudo update-checker --dry-run --skip-apt-update          # faster, uses existing package lists
sudo update-checker --dry-run --html /tmp/report.html    # also save the HTML email to look at
update-checker --help
```

Check names for `--only`: `apt, reboot, snap, pro, unattended_upgrades, disk, pihole, docker`.

---

## Running a check manually

Send a real report right now, exactly as the timer would:

```bash
sudo systemctl start update-checker.service
journalctl -u update-checker.service -n 50 --no-pager
```

Or run it directly in the terminal (also emails):

```bash
sudo update-checker
```

Exit codes: `0` OK (sent, or skipped because everything is up to date),
`1` email failed, `2` missing API key or recipient. If sending fails the full
text report is written to the log so it isn't lost.

---

## Viewing logs

```bash
journalctl -u update-checker.service                 # all runs
journalctl -u update-checker.service -n 100          # last 100 lines
journalctl -u update-checker.service --since today
journalctl -u update-checker.service -f              # follow a run live
systemctl status update-checker.service              # result of the last run
systemctl list-timers update-checker.timer           # when it last ran / runs next
```

Each run logs every check's result and the subject line, then
`Email sent to ... (id ...)`. The Resend dashboard also shows delivery status.

---

## Changing the schedule

The timer (`/etc/systemd/system/update-checker.timer`) is:

```ini
[Timer]
OnUnitActiveSec=3d      # every 3 days, counted from the last run
Persistent=true
OnBootSec=15min         # run 15 min after boot
RandomizedDelaySec=5min
```

A note on catching up missed runs: systemd only applies `Persistent=true` to
`OnCalendar=` timers. With `OnUnitActiveSec=` the 3-day countdown restarts when
the machine boots, so `OnBootSec=15min` is what makes sure a report is sent
after the machine has been off. It also means a reboot triggers a report, and
the countdown starts again from there.

To change it, use a drop-in override (survives re-running `install.sh`):

```bash
sudo systemctl edit update-checker.timer
```

and put, for example:

```ini
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=1d
```

(the empty line clears the original value). Or switch to fixed calendar times,
where `Persistent=true` does catch up missed runs:

```ini
[Timer]
OnUnitActiveSec=
OnBootSec=
OnCalendar=Mon,Thu 08:00
Persistent=true
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart update-checker.timer
systemctl list-timers update-checker.timer
```

Remove the override with `sudo systemctl revert update-checker.timer`.

---

## Uninstall

```bash
sudo ./uninstall.sh                # asks whether to delete /etc/update-checker
sudo ./uninstall.sh --purge        # also delete config + API key (secret.env is shredded)
sudo ./uninstall.sh --keep-config  # keep /etc/update-checker for a later reinstall
```

Stops and removes the timer and service, the script and `/usr/local/share/update-checker`.

---

## Files

| Path (installed) | |
|---|---|
| `/usr/local/sbin/update-checker` | the program (`update_checker.py` in the repo) |
| `/etc/update-checker/config` | per-machine config |
| `/etc/update-checker/secret.env` | `RESEND_API_KEY`, optional `GITHUB_TOKEN`. root:root, 600 |
| `/etc/systemd/system/update-checker.{service,timer}` | systemd units |
| `/usr/local/share/update-checker/` | config template and machine examples, for reference |

| Path (repo) | |
|---|---|
| `update_checker.py` | the program |
| `install.sh`, `uninstall.sh` | installer / remover |
| `config/config.example` | fully commented config template |
| `config/secret.env.example` | secrets template (placeholders only) |
| `examples/{optiplex,pihole,droplet}.conf` | per-machine example configs |
| `systemd/` | service and timer |
| `tests/` | unit tests: `python3 -m unittest discover -s tests` |

Secrets are never stored in the repo; `.gitignore` excludes `secret.env` and
`*.env` files.
