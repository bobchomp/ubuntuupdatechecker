#!/usr/bin/python3
"""update-checker: report-only update checker for Ubuntu Server machines.

Runs a set of checks (apt, reboot, snaps, Ubuntu Pro, unattended-upgrades,
disk space, Pi-hole, Docker containers) and emails one HTML report via the
Resend HTTPS API. It never installs, upgrades, restarts or removes anything;
the only state-changing command it runs is `apt-get update`, which refreshes
the package lists.

Python 3 standard library only.
"""

import argparse
import base64
import configparser
import datetime
import hashlib
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
DEFAULT_CONFIG = "/etc/update-checker/config"
DEFAULT_SECRETS = "/etc/update-checker/secret.env"
USER_AGENT = "update-checker/%s (+https://github.com/bobchomp/ubuntuupdatechecker)" % VERSION
HTTP_TIMEOUT = 20

CHECK_ORDER = ["apt", "reboot", "snap", "pro", "unattended_upgrades", "disk", "pihole", "docker"]

# Tags treated as "floating" (compared by digest) in addition to any tag that
# contains no digits at all. Extend per machine with [docker] floating_tags.
DEFAULT_FLOATING_TAGS = {
    "latest", "stable", "main", "master", "release", "edge", "nightly",
    "develop", "dev", "beta", "lts", "current", "mainline", "rolling",
}

MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

# Severity, lowest to highest. Colours are used in the HTML email.
STATUS_RANK = {"skipped": 0, "ok": 1, "info": 1, "update": 2, "warn": 3, "error": 3, "alert": 4}
STATUS_COLOUR = {
    "ok": "#1a7f37", "info": "#0969da", "update": "#9a6700", "warn": "#bc4c00",
    "alert": "#cf222e", "error": "#8250df", "skipped": "#6e7781",
}
STATUS_LABEL = {
    "ok": "OK", "info": "INFO", "update": "UPDATES", "warn": "WARNING",
    "alert": "ACTION", "error": "FAILED", "skipped": "SKIPPED",
}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Config and secrets
# --------------------------------------------------------------------------

class Config:
    def __init__(self, path):
        self.path = path
        cp = configparser.ConfigParser(
            delimiters=("=",), interpolation=None,
            inline_comment_prefixes=("#", ";"), strict=False,
        )
        if path:
            if not os.path.exists(path):
                raise SystemExit("Config file not found: %s" % path)
            cp.read(path, encoding="utf-8")
        self.cp = cp

        self.label = self.get("general", "label", socket.gethostname())
        self.recipients = split_list(self.get("general", "recipient", ""))
        self.from_address = self.get("general", "from_address", "info@rossmackenzie.co.uk")
        self.from_name = self.get("general", "from_name", "Update Checker")
        self.send_when_up_to_date = self.getbool("general", "send_when_up_to_date", True)

        self.mount_points = split_list(self.get("disk", "mount_points", "/")) or ["/"]
        self.disk_warn_percent = self.getint("disk", "warn_percent", 80)

        floating = split_list(self.get("docker", "floating_tags", ""))
        self.floating_tags = DEFAULT_FLOATING_TAGS | {t.lower() for t in floating}
        self.ignore_containers = set(split_list(self.get("docker", "ignore_containers", "")))
        self.digest_check_unmapped = self.getbool("docker", "digest_check_unmapped", False)

        # image (normalised to registry/repository) -> release source string
        self.image_sources = {}
        if cp.has_section("docker.images"):
            for key, value in cp.items("docker.images"):
                value = value.strip()
                if not value:
                    continue
                try:
                    ref = parse_image_ref(key)
                except ValueError:
                    log("config: ignoring invalid image name in [docker.images]: %s" % key)
                    continue
                self.image_sources[ref["name"]] = value

    def get(self, section, key, default):
        try:
            value = self.cp.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default
        value = value.strip()
        return value if value != "" else default

    def getbool(self, section, key, default):
        value = self.get(section, key, None)
        if value is None:
            return default
        return value.lower() in ("1", "yes", "true", "on")

    def getint(self, section, key, default):
        value = self.get(section, key, None)
        try:
            return int(value) if value is not None else default
        except ValueError:
            log("config: %s.%s is not a number, using %s" % (section, key, default))
            return default

    def check_enabled(self, name):
        return self.getbool("checks", name, True)


def split_list(value):
    if not value:
        return []
    return [p.strip() for p in re.split(r"[,\s]+", value) if p.strip()]


def load_secrets(path):
    """Read KEY=value lines. Environment variables take precedence."""
    secrets = {}
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    if key.startswith("export "):
                        key = key[len("export "):].strip()
                    value = value.strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                        value = value[1:-1]
                    secrets[key] = value
        except PermissionError:
            log("Cannot read %s (permission denied) - run as root." % path)
    for key in ("RESEND_API_KEY", "GITHUB_TOKEN"):
        if os.environ.get(key):
            secrets[key] = os.environ[key]
    return secrets


# --------------------------------------------------------------------------
# Helpers: subprocess and HTTP
# --------------------------------------------------------------------------

def run(cmd, timeout=120, env_extra=None):
    """Run a command, return (returncode, stdout, stderr). Never raises for
    a non-zero exit; raises RuntimeError if the command can't be started or
    times out."""
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "LANG": "C", "DEBIAN_FRONTEND": "noninteractive"})
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            timeout=timeout, env=env, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("command not found: %s" % cmd[0])
    except subprocess.TimeoutExpired:
        raise RuntimeError("timed out after %ss: %s" % (timeout, " ".join(cmd)))
    return (proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


class HTTPResult:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body.decode("utf-8"))


def http(url, method="GET", headers=None, data=None, timeout=HTTP_TIMEOUT):
    """HTTP request that returns HTTPResult for any HTTP status (no raise on
    4xx/5xx). Network errors raise RuntimeError."""
    hdrs = {"User-Agent": USER_AGENT}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, method=method, headers=hdrs, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HTTPResult(resp.status, resp.headers, resp.read(10 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(1024 * 1024)
        except Exception:
            body = b""
        return HTTPResult(exc.code, exc.headers, body)
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError("%s: %s" % (urllib.parse.urlsplit(url).netloc, reason))


# --------------------------------------------------------------------------
# Report model and rendering
# --------------------------------------------------------------------------

class CheckResult:
    def __init__(self, key, title):
        self.key = key
        self.title = title
        self.status = "ok"
        self.summary = ""
        self.blocks = []        # renderable content, see add_* below
        self.subject = []       # short phrases for the email subject

    def raise_status(self, status):
        if STATUS_RANK[status] >= STATUS_RANK[self.status]:
            self.status = status

    def add_para(self, text, level=None):
        self.blocks.append(("para", text, level))

    def add_list(self, items, level=None):
        if items:
            self.blocks.append(("list", list(items), level))

    def add_table(self, headers, rows, levels=None):
        """levels: optional per-row status used to colour the row."""
        if rows:
            self.blocks.append(("table", headers, rows, levels or [None] * len(rows)))

    def add_pre(self, text):
        if text.strip():
            self.blocks.append(("pre", text.rstrip()))


def skipped(result, reason):
    result.status = "skipped"
    result.summary = reason
    return result


def render_text(label, results, subject):
    out = []
    out.append("=" * 72)
    out.append("Subject: %s" % subject)
    out.append("=" * 72)
    out.append("Machine: %s (%s)   %s" % (label, socket.getfqdn(), os_pretty_name()))
    out.append("Generated: %s" % now_str())
    out.append("")
    out.append("SUMMARY")
    width = max(len(r.title) for r in results)
    for r in results:
        out.append("  %-9s %-*s  %s" % ("[" + STATUS_LABEL[r.status] + "]", width, r.title, r.summary))
    for r in results:
        out.append("")
        out.append("-" * 72)
        out.append("%s  [%s]" % (r.title.upper(), STATUS_LABEL[r.status]))
        out.append("-" * 72)
        out.append(r.summary)
        for block in r.blocks:
            kind = block[0]
            if kind == "para":
                prefix = "!! " if block[2] in ("alert", "warn", "error") else ""
                out.append(prefix + block[1])
            elif kind == "list":
                prefix = "!! " if block[2] in ("alert", "warn", "error") else ""
                for item in block[1]:
                    out.append("  %s- %s" % (prefix, item))
            elif kind == "pre":
                out.extend("    " + line for line in block[1].splitlines())
            elif kind == "table":
                headers, rows, levels = block[1], block[2], block[3]
                rows_s = [[str(c) for c in row] for row in rows]
                widths = [len(h) for h in headers]
                for row in rows_s:
                    for i, cell in enumerate(row):
                        widths[i] = max(widths[i], len(cell))
                fmt = "  ".join("%-" + str(w) + "s" for w in widths)
                out.append("    " + (fmt % tuple(headers)).rstrip())
                out.append("    " + "  ".join("-" * w for w in widths))
                for row, level in zip(rows_s, levels):
                    mark = "!! " if level in ("alert", "warn", "error") else ""
                    out.append(("    " + fmt % tuple(row)).rstrip() + ("  " + mark.strip() if mark else ""))
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def render_html(label, results, subject):
    e = html.escape
    row_bg = {"alert": "#ffebe9", "warn": "#fff1e5", "error": "#fbefff", "update": "#fff8c5"}

    def badge(status):
        return ('<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
                'font-size:11px;font-weight:bold;color:#fff;background:%s">%s</span>'
                % (STATUS_COLOUR[status], STATUS_LABEL[status]))

    def block_html(block):
        kind = block[0]
        if kind == "para":
            level = block[2]
            if level in row_bg:
                return ('<p style="margin:8px 0;padding:8px 10px;border-radius:4px;background:%s;'
                        'color:%s;font-weight:bold">%s</p>' % (row_bg[level], STATUS_COLOUR[level], e(block[1])))
            return '<p style="margin:8px 0">%s</p>' % e(block[1])
        if kind == "list":
            level = block[2]
            style = ' style="color:%s;font-weight:bold"' % STATUS_COLOUR[level] if level in row_bg else ""
            items = "".join("<li%s>%s</li>" % (style, e(str(i))) for i in block[1])
            return '<ul style="margin:6px 0;padding-left:22px">%s</ul>' % items
        if kind == "pre":
            return ('<pre style="background:#f6f8fa;padding:8px;border-radius:4px;font-size:12px;'
                    'white-space:pre-wrap;margin:8px 0">%s</pre>' % e(block[1]))
        if kind == "table":
            headers, rows, levels = block[1], block[2], block[3]
            th = "".join('<th style="text-align:left;padding:4px 8px;border-bottom:2px solid #d0d7de;'
                         'font-size:12px">%s</th>' % e(h) for h in headers)
            trs = []
            for row, level in zip(rows, levels):
                bg = row_bg.get(level, "")
                colour = STATUS_COLOUR[level] if level in row_bg else "#1f2328"
                weight = "bold" if level in ("alert",) else "normal"
                tds = "".join('<td style="padding:4px 8px;border-bottom:1px solid #eaeef2;font-size:12px;'
                              'color:%s;font-weight:%s">%s</td>' % (colour, weight, e(str(c))) for c in row)
                trs.append('<tr style="background:%s">%s</tr>' % (bg, tds))
            return ('<table cellspacing="0" cellpadding="0" style="border-collapse:collapse;width:100%%;'
                    'margin:8px 0">%s%s</table>' % ("<tr>%s</tr>" % th, "".join(trs)))
        return ""

    overall = max((r.status for r in results), key=lambda s: STATUS_RANK[s])
    parts = []
    parts.append('<!doctype html><html><body style="margin:0;padding:0;background:#f6f8fa;'
                 'font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2328">')
    parts.append('<div style="max-width:760px;margin:0 auto;padding:16px">')
    parts.append('<div style="background:#fff;border:1px solid #d0d7de;border-top:6px solid %s;'
                 'border-radius:6px;padding:16px 20px">' % STATUS_COLOUR[overall if overall != "skipped" else "ok"])
    parts.append('<h1 style="font-size:20px;margin:0 0 4px">%s</h1>' % e(subject))
    parts.append('<div style="font-size:12px;color:#57606a">%s &middot; %s &middot; %s</div>'
                 % (e(socket.getfqdn()), e(os_pretty_name()), e(now_str())))
    parts.append('<table cellspacing="0" cellpadding="0" style="border-collapse:collapse;width:100%;margin-top:14px">')
    for r in results:
        bg = row_bg.get(r.status, "")
        parts.append('<tr style="background:%s"><td style="padding:6px 8px;border-bottom:1px solid #eaeef2;'
                     'white-space:nowrap;width:1%%">%s</td><td style="padding:6px 8px;border-bottom:1px solid '
                     '#eaeef2;font-weight:bold;white-space:nowrap;width:1%%"><a href="#%s" style="color:#1f2328;'
                     'text-decoration:none">%s</a></td><td style="padding:6px 8px;border-bottom:1px solid #eaeef2;'
                     'font-size:13px">%s</td></tr>'
                     % (bg, badge(r.status), r.key, e(r.title), e(r.summary)))
    parts.append("</table></div>")
    for r in results:
        parts.append('<div id="%s" style="background:#fff;border:1px solid #d0d7de;border-left:6px solid %s;'
                     'border-radius:6px;padding:12px 16px;margin-top:14px">' % (r.key, STATUS_COLOUR[r.status]))
        parts.append('<h2 style="font-size:16px;margin:0 0 6px">%s %s</h2>' % (e(r.title), badge(r.status)))
        parts.append('<p style="margin:4px 0 8px;color:#57606a">%s</p>' % e(r.summary))
        parts.extend(block_html(b) for b in r.blocks)
        parts.append("</div>")
    parts.append('<p style="font-size:11px;color:#8c959f;text-align:center;margin-top:16px">'
                 'update-checker %s &middot; report only, nothing was changed on this machine</p>' % VERSION)
    parts.append("</div></body></html>")
    return "\n".join(parts)


def now_str():
    return datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")


def os_pretty_name():
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown OS"


def plural(n, word, plural_word=None):
    return "%d %s" % (n, word if n == 1 else (plural_word or word + "s"))


# --------------------------------------------------------------------------
# Check 1: apt packages
# --------------------------------------------------------------------------

APT_LIST_RE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<suites>\S+)\s+(?P<new>\S+)\s+(?P<arch>\S+)\s+\[upgradable from: (?P<old>[^\]]+)\]")


def parse_apt_upgradable(text):
    pkgs = []
    for line in text.splitlines():
        m = APT_LIST_RE.match(line.strip())
        if not m:
            continue
        suites = m.group("suites").split(",")
        pkgs.append({
            "name": m.group("name"),
            "suites": suites,
            "new": m.group("new"),
            "old": m.group("old"),
            "arch": m.group("arch"),
            "security": any("security" in s for s in suites),
        })
    return pkgs


def parse_madison(text):
    """apt-cache madison output -> {pkg: [(version, source), ...]}"""
    out = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            out.setdefault(parts[0], []).append((parts[1], parts[2]))
    return out


def refine_security(pkgs):
    """A package whose candidate is in -updates may still carry a security fix
    (a newer-than-installed version also exists in -security). Ubuntu's MOTD
    counts those as security updates too, so do the same."""
    others = [p for p in pkgs if not p["security"]]
    if not others:
        return
    rc, out, _ = run(["apt-cache", "madison"] + [p["name"] for p in others], timeout=120)
    if rc != 0:
        return
    madison = parse_madison(out)
    for p in others:
        for version, source in madison.get(p["name"], []):
            if "security" not in source or version == p["old"]:
                continue
            rc, _, _ = run(["dpkg", "--compare-versions", version, "gt", p["old"]], timeout=30)
            if rc == 0:
                p["security"] = True
                break


def check_apt(cfg, args):
    r = CheckResult("apt", "System packages")
    if not shutil.which("apt-get"):
        return skipped(r, "apt not installed")
    if args.skip_apt_update:
        r.add_para("apt update skipped (--skip-apt-update); package lists may be stale.", "warn")
    else:
        log("apt: running apt-get update")
        try:
            rc, out, err = run(["apt-get", "update", "-q", "-o", "DPkg::Lock::Timeout=300"], timeout=900)
        except RuntimeError as exc:
            rc, out, err = 1, "", str(exc)
        problems = [l.strip() for l in (out + "\n" + err).splitlines() if re.match(r"^\s*(E|W|Err):", l)]
        if rc != 0:
            r.raise_status("error")
            r.add_para("apt-get update failed (exit %s); results below use the existing package lists." % rc, "error")
            r.subject.append("apt update failed")
        if problems:
            r.raise_status("warn" if rc == 0 else "error")
            r.add_para("apt update reported:", "warn")
            r.add_pre("\n".join(problems[:30]))

    rc, out, err = run(["apt", "list", "--upgradable"], timeout=120)
    if rc != 0:
        raise RuntimeError("apt list --upgradable failed: %s" % err.strip()[:300])
    pkgs = parse_apt_upgradable(out)
    try:
        refine_security(pkgs)
    except RuntimeError as exc:
        log("apt: security refinement skipped: %s" % exc)

    sec = sorted((p for p in pkgs if p["security"]), key=lambda p: p["name"])
    reg = sorted((p for p in pkgs if not p["security"]), key=lambda p: p["name"])
    if not pkgs:
        r.summary = "All packages up to date"
        return r

    r.summary = "%s (%d security)" % (plural(len(pkgs), "upgradable package"), len(sec))
    r.subject.append("%s (%d security)" % (plural(len(pkgs), "update"), len(sec)) if sec
                     else plural(len(pkgs), "update"))
    r.raise_status("alert" if sec else "update")
    if sec:
        r.add_para("Security updates: %d" % len(sec), "alert")
        r.add_table(["Package", "Installed", "Available", "Pocket"],
                    [[p["name"], p["old"], p["new"], ", ".join(p["suites"])] for p in sec],
                    ["alert"] * len(sec))
    if reg:
        r.add_para("Other updates: %d" % len(reg))
        r.add_table(["Package", "Installed", "Available", "Pocket"],
                    [[p["name"], p["old"], p["new"], ", ".join(p["suites"])] for p in reg])
    r.add_para("Apply with: sudo apt upgrade (or sudo apt full-upgrade). "
               "Some packages may be held back by phased updates.")
    return r


# --------------------------------------------------------------------------
# Check 2: reboot required
# --------------------------------------------------------------------------

def check_reboot(cfg, args):
    r = CheckResult("reboot", "Reboot required")
    flag, pkgs_file = "/var/run/reboot-required", "/var/run/reboot-required.pkgs"
    if not os.path.exists(flag):
        r.summary = "No reboot required"
        return r
    pkgs = []
    if os.path.exists(pkgs_file):
        with open(pkgs_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip() and line.strip() not in pkgs:
                    pkgs.append(line.strip())
    since = datetime.datetime.fromtimestamp(os.path.getmtime(flag)).strftime("%Y-%m-%d %H:%M")
    r.raise_status("alert")
    r.summary = "Reboot required (since %s)" % since
    r.subject.append("reboot needed")
    r.add_para("A reboot is required to finish applying updates (flag set %s)." % since, "alert")
    if pkgs:
        r.add_para("Packages requesting the reboot:")
        r.add_list(pkgs)
    return r


# --------------------------------------------------------------------------
# Check 3: snaps
# --------------------------------------------------------------------------

def parse_snap_refresh_list(text):
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines or not lines[0].startswith("Name"):
        return []
    snaps = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2:
            snaps.append({"name": parts[0], "version": parts[1],
                          "rev": parts[2] if len(parts) > 2 else ""})
    return snaps


def check_snap(cfg, args):
    r = CheckResult("snap", "Snaps")
    if not shutil.which("snap"):
        return skipped(r, "snap not installed")
    rc, out, err = run(["snap", "refresh", "--list"], timeout=180)
    if rc != 0:
        raise RuntimeError("snap refresh --list failed: %s" % (err.strip() or out.strip())[:300])
    snaps = parse_snap_refresh_list(out)
    if not snaps:
        r.summary = "All snaps up to date"
        return r
    r.raise_status("update")
    r.summary = plural(len(snaps), "snap update") + " available"
    r.subject.append(plural(len(snaps), "snap update"))
    r.add_table(["Snap", "New version", "Revision"], [[s["name"], s["version"], s["rev"]] for s in snaps])
    r.add_para("Snaps normally refresh automatically; apply now with: sudo snap refresh")
    return r


# --------------------------------------------------------------------------
# Check 4: Ubuntu Pro
# --------------------------------------------------------------------------

def check_pro(cfg, args):
    r = CheckResult("pro", "Ubuntu Pro")
    if not shutil.which("pro"):
        return skipped(r, "pro not installed")
    rc, out, err = run(["pro", "security-status", "--format", "json"], timeout=180)
    data = None
    if rc == 0:
        try:
            data = json.loads(out)
        except ValueError:
            data = None
    if data is None:
        rc2, out2, err2 = run(["pro", "security-status"], timeout=180)
        if rc2 != 0:
            raise RuntimeError("pro security-status failed: %s" % (err2.strip() or err.strip())[:300])
        r.summary = "See details"
        r.add_pre(out2)
        return r

    summary = data.get("summary", {})
    ua = summary.get("ua", {})
    attached = ua.get("attached")
    enabled = ua.get("enabled_services") or []
    rows = [["Attached to Ubuntu Pro", "yes" if attached else "no"],
            ["Enabled services", ", ".join(enabled) if enabled else "none"]]
    labels = [
        ("num_installed_packages", "Installed packages"),
        ("num_main_packages", "  from main"),
        ("num_restricted_packages", "  from restricted"),
        ("num_universe_packages", "  from universe"),
        ("num_multiverse_packages", "  from multiverse"),
        ("num_third_party_packages", "  third-party"),
        ("num_unknown_packages", "  unknown origin"),
        ("num_esm_infra_packages", "  from esm-infra"),
        ("num_esm_apps_packages", "  from esm-apps"),
        ("num_standard_security_updates", "Standard security updates available"),
        ("num_esm_infra_updates", "esm-infra updates available"),
        ("num_esm_apps_updates", "esm-apps updates available"),
    ]
    for key, label in labels:
        if key in summary and summary[key] is not None:
            rows.append([label, summary[key]])
    r.add_table(["Item", "Value"], rows)

    universe = summary.get("num_universe_packages") or 0
    esm_updates = (summary.get("num_esm_infra_updates") or 0) + (summary.get("num_esm_apps_updates") or 0)
    if attached:
        r.summary = "Attached (%s)" % (", ".join(enabled) or "no services enabled")
    else:
        r.summary = "Not attached"
        r.status = "info"
        if universe:
            r.add_para("%d installed packages come from universe and only receive security updates "
                       "with Ubuntu Pro (esm-apps). Free for up to 5 machines: https://ubuntu.com/pro"
                       % universe)
    if esm_updates:
        if attached:
            r.summary += "; %s pending (listed under System packages)" % plural(esm_updates, "ESM update")
        else:
            r.raise_status("warn")
            r.summary += "; %s available with Pro" % plural(esm_updates, "ESM security update")
            r.add_para("%s would be available by attaching Ubuntu Pro." % plural(esm_updates, "ESM security update"),
                       "warn")
    return r


# --------------------------------------------------------------------------
# Check 5: unattended-upgrades
# --------------------------------------------------------------------------

def parse_apt_config_dump(text, key):
    m = re.search(r'^%s\s+"([^"]*)";' % re.escape(key), text, re.M)
    return m.group(1) if m else None


def check_unattended(cfg, args):
    r = CheckResult("unattended_upgrades", "Unattended upgrades")
    problems = []
    rc, out, _ = run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"], timeout=30)
    installed = rc == 0 and out.strip().endswith(" installed")
    rows = [["Package installed", "yes" if installed else "no"]]
    if not installed:
        problems.append("unattended-upgrades is not installed (sudo apt install unattended-upgrades)")
    rc, dump, _ = run(["apt-config", "dump"], timeout=30)
    lists = parse_apt_config_dump(dump, "APT::Periodic::Update-Package-Lists")
    uu = parse_apt_config_dump(dump, "APT::Periodic::Unattended-Upgrade")
    rows.append(["APT::Periodic::Update-Package-Lists", lists if lists is not None else "(not set)"])
    rows.append(["APT::Periodic::Unattended-Upgrade", uu if uu is not None else "(not set)"])
    if uu in (None, "", "0"):
        problems.append("APT::Periodic::Unattended-Upgrade is not enabled "
                        "(run: sudo dpkg-reconfigure -plow unattended-upgrades)")
    if lists in (None, "", "0"):
        problems.append("APT::Periodic::Update-Package-Lists is not enabled")

    if shutil.which("systemctl"):
        for timer in ("apt-daily.timer", "apt-daily-upgrade.timer"):
            _, en, _ = run(["systemctl", "is-enabled", timer], timeout=30)
            _, act, _ = run(["systemctl", "is-active", timer], timeout=30)
            en, act = en.strip() or "unknown", act.strip() or "unknown"
            rows.append([timer, "%s, %s" % (en, act)])
            if en not in ("enabled", "static") or act != "active":
                problems.append("%s is %s/%s" % (timer, en, act))

    last = last_unattended_run()
    if last:
        rows.append(["Last unattended-upgrades log entry", last])
    r.add_table(["Setting", "Value"], rows)
    if problems:
        r.raise_status("warn")
        r.summary = "Not fully enabled"
        r.subject.append("unattended-upgrades off")
        r.add_list(problems, "warn")
    else:
        r.summary = "Installed and enabled"
    return r


def last_unattended_run():
    path = "/var/log/unattended-upgrades/unattended-upgrades.log"
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - 4096))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------
# Check 6: disk space
# --------------------------------------------------------------------------

def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024


def check_disk(cfg, args):
    r = CheckResult("disk", "Disk space")
    rows, levels, warnings = [], [], []
    for mp in cfg.mount_points:
        if not os.path.exists(mp):
            rows.append([mp, "-", "-", "-", "-", "path does not exist"])
            levels.append("warn")
            warnings.append("%s does not exist" % mp)
            continue
        st = os.statvfs(mp)
        total = st.f_blocks * st.f_frsize
        free_root = st.f_bfree * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        used = total - free_root
        # Same formula as df: used / (used + available to non-root)
        pct = int(-(-used * 100 // (used + avail))) if (used + avail) else 0
        note = ""
        level = None
        if mp != "/" and not os.path.ismount(mp):
            note = "NOT MOUNTED - figures are for the parent filesystem"
            level = "alert"
            warnings.append("%s is not mounted" % mp)
        if pct >= cfg.disk_warn_percent:
            note = (note + "; " if note else "") + "above %d%%" % cfg.disk_warn_percent
            level = "alert"
            warnings.append("%s at %d%%" % (mp, pct))
        rows.append([mp, "%d%%" % pct, human_bytes(used), human_bytes(avail), human_bytes(total), note or "ok"])
        levels.append(level)
    r.add_table(["Mount", "Used %", "Used", "Free", "Size", "Status"],
                rows, levels)
    if warnings:
        r.raise_status("alert")
        r.summary = "; ".join(warnings)
        r.subject.append("disk " + ", ".join(warnings))
    else:
        r.summary = "All mounts below %d%%" % cfg.disk_warn_percent
    return r


# --------------------------------------------------------------------------
# Check 7: Pi-hole
# --------------------------------------------------------------------------

PIHOLE_RE = re.compile(r"^\s*(?P<comp>[\w\- ]+?)\s+version is\s+(?P<cur>\S+)(?:\s+\(Latest:\s*(?P<latest>[^)]*)\))?",
                       re.I)
PIHOLE_NAMES = {"pi-hole": "Core", "core": "Core", "adminlte": "Web interface", "web": "Web interface",
                "web interface": "Web interface", "ftl": "FTL"}


def parse_pihole_version(text):
    comps = []
    for line in text.splitlines():
        m = PIHOLE_RE.match(line)
        if not m:
            continue
        name = PIHOLE_NAMES.get(m.group("comp").strip().lower(), m.group("comp").strip())
        latest = (m.group("latest") or "").strip()
        if latest.lower() in ("", "null", "n/a", "unknown"):
            latest = None
        comps.append({"name": name, "current": m.group("cur"), "latest": latest})
    return comps


def check_pihole(cfg, args):
    r = CheckResult("pihole", "Pi-hole")
    if not shutil.which("pihole"):
        return skipped(r, "Pi-hole not installed")
    rc, out, err = run(["pihole", "-v"], timeout=120)
    comps = parse_pihole_version(out)
    if not comps:
        raise RuntimeError("could not parse 'pihole -v' output: %s" % (out + err).strip()[:300])
    rows, levels, outdated = [], [], []
    for c in comps:
        if c["latest"] is None:
            state, level = "latest unknown", "warn"
        elif version_tuple(c["latest"]) and version_tuple(c["current"]):
            newer = cmp_versions(c["current"], c["latest"]) < 0
            state, level = ("update available", "update") if newer else ("up to date", None)
        else:
            newer = c["latest"].lstrip("vV") != c["current"].lstrip("vV")
            state, level = ("update available", "update") if newer else ("up to date", None)
        if level == "update":
            outdated.append(c["name"])
        rows.append([c["name"], c["current"], c["latest"] or "?", state])
        levels.append(level)
    r.add_table(["Component", "Installed", "Latest", "Status"], rows, levels)
    if outdated:
        r.raise_status("update")
        r.summary = "Update available: " + ", ".join(outdated)
        r.subject.append("Pi-hole update")
        r.add_para("Apply with: sudo pihole -up")
    elif any(l == "warn" for l in levels):
        r.raise_status("warn")
        r.summary = "Could not determine latest versions (Pi-hole's own update check may not have run yet)"
    else:
        r.summary = "Up to date"
    return r


# --------------------------------------------------------------------------
# Version helpers
# --------------------------------------------------------------------------

VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*")


def version_tuple(text):
    """First dotted-number run in text -> tuple of ints, or None."""
    if not text:
        return None
    m = VERSION_TOKEN_RE.search(text)
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def cmp_versions(a, b):
    ta, tb = version_tuple(a), version_tuple(b)
    if ta is None or tb is None:
        raise ValueError("not a version")
    n = max(len(ta), len(tb))
    ta, tb = ta + (0,) * (n - len(ta)), tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def tag_skeleton(tag):
    """'v4.10.8-alpine' -> 'v#.#.#-alpine'. Tags with the same skeleton are
    comparable versions of the same flavour."""
    return re.sub(r"\d+", "#", tag)


def tag_numbers(tag):
    return tuple(int(x) for x in re.findall(r"\d+", tag))


def best_matching_tag(current, tags):
    """Highest tag with the same shape as `current`, or None."""
    skel = tag_skeleton(current)
    candidates = [t for t in tags if tag_skeleton(t) == skel]
    if not candidates:
        return None
    return max(candidates, key=tag_numbers)


# --------------------------------------------------------------------------
# Docker registry client
# --------------------------------------------------------------------------

def parse_image_ref(ref):
    """Split an image reference into registry, repository, tag and digest.

    'nginx' -> docker.io/library/nginx:latest
    'ghcr.io/immich-app/immich-server:v1.2.3@sha256:..' -> registry ghcr.io ...
    """
    ref = ref.strip()
    if not ref or re.search(r"\s", ref):
        raise ValueError("bad image reference: %r" % ref)
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", ref
    if registry in ("index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"):
        registry = "docker.io"
    if registry == "docker.io" and "/" not in repo:
        repo = "library/" + repo
    repo = repo.lower()
    return {
        "registry": registry.lower(),
        "repo": repo,
        "tag": tag,
        "digest": digest,
        "name": "%s/%s" % (registry.lower(), repo),
    }


class Registry:
    """Minimal anonymous (or docker-config-authenticated) OCI registry client."""

    def __init__(self):
        self.tokens = {}
        self.docker_auths = self._load_docker_auths()

    @staticmethod
    def _load_docker_auths():
        auths = {}
        for path in ("/root/.docker/config.json", os.path.expanduser("~/.docker/config.json")):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            for host, entry in (data.get("auths") or {}).items():
                if entry.get("auth"):
                    host = re.sub(r"^https?://", "", host).split("/")[0]
                    if host in ("index.docker.io", "registry-1.docker.io"):
                        host = "docker.io"
                    auths[host] = entry["auth"]
        return auths

    @staticmethod
    def api_host(registry):
        return "registry-1.docker.io" if registry == "docker.io" else registry

    def _get_token(self, registry, repo, challenge):
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.get("realm")
        if not realm:
            raise RuntimeError("registry %s sent an auth challenge without a realm" % registry)
        query = {"scope": params.get("scope") or "repository:%s:pull" % repo}
        if params.get("service"):
            query["service"] = params["service"]
        headers = {}
        if registry in self.docker_auths:
            headers["Authorization"] = "Basic " + self.docker_auths[registry]
        resp = http(realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query), headers=headers)
        if resp.status != 200:
            raise RuntimeError("registry token request to %s failed (HTTP %s)" % (registry, resp.status))
        data = resp.json()
        token = data.get("token") or data.get("access_token")
        if not token:
            raise RuntimeError("registry %s returned no token" % registry)
        return "Bearer " + token

    def request(self, registry, repo, path, method="GET", accept=None):
        url = "https://%s/v2/%s/%s" % (self.api_host(registry), repo, path)
        key = (registry, repo)
        headers = {"Accept": accept} if accept else {}
        if key in self.tokens:
            headers["Authorization"] = self.tokens[key]
        resp = http(url, method=method, headers=headers)
        if resp.status == 401:
            challenge = resp.headers.get("WWW-Authenticate", "")
            if challenge.lower().startswith("bearer"):
                self.tokens[key] = self._get_token(registry, repo, challenge)
            elif challenge.lower().startswith("basic") and registry in self.docker_auths:
                self.tokens[key] = "Basic " + self.docker_auths[registry]
            else:
                raise RuntimeError("%s requires authentication for %s" % (registry, repo))
            headers["Authorization"] = self.tokens[key]
            resp = http(url, method=method, headers=headers)
        return resp

    def manifest_digest(self, registry, repo, tag):
        resp = self.request(registry, repo, "manifests/" + tag, method="HEAD", accept=MANIFEST_ACCEPT)
        if resp.status == 404:
            raise RuntimeError("tag %s not found in %s/%s" % (tag, registry, repo))
        digest = resp.headers.get("Docker-Content-Digest")
        if resp.status in (405, 400) or (resp.status == 200 and not digest):
            # Some registries don't support HEAD or omit the header; fall back to GET.
            resp = self.request(registry, repo, "manifests/" + tag, accept=MANIFEST_ACCEPT)
            digest = resp.headers.get("Docker-Content-Digest")
            if resp.status == 200 and not digest:
                digest = "sha256:" + hashlib.sha256(resp.body).hexdigest()
        if resp.status == 429:
            raise RuntimeError("%s rate limit reached" % registry)
        if resp.status != 200:
            raise RuntimeError("manifest lookup %s/%s:%s failed (HTTP %s)" % (registry, repo, tag, resp.status))
        return digest

    def list_tags(self, registry, repo, max_pages=50):
        tags = []
        path = "tags/list?n=1000"
        for _ in range(max_pages):
            resp = self.request(registry, repo, path)
            if resp.status == 429:
                raise RuntimeError("%s rate limit reached" % registry)
            if resp.status != 200:
                raise RuntimeError("tag list for %s/%s failed (HTTP %s)" % (registry, repo, resp.status))
            tags.extend(resp.json().get("tags") or [])
            link = resp.headers.get("Link", "")
            m = re.search(r"<([^>]+)>;\s*rel=\"?next\"?", link)
            if not m:
                break
            nxt = m.group(1)
            # Link is usually '/v2/<repo>/tags/list?...'; keep only the part after tags/
            path = "tags/list" + nxt.split("tags/list", 1)[1] if "tags/list" in nxt else None
            if not path:
                break
        else:
            log("docker: tag list for %s/%s truncated at %d tags" % (registry, repo, len(tags)))
        return tags


# --------------------------------------------------------------------------
# Release sources
# --------------------------------------------------------------------------

class ReleaseSources:
    def __init__(self, registry, github_token=None):
        self.registry = registry
        self.github_token = github_token
        self.cache = {}

    def latest(self, source, image):
        """Return the latest release tag for a source spec, cached."""
        key = (source, image["name"])
        if key not in self.cache:
            try:
                self.cache[key] = ("ok", self._latest(source, image))
            except Exception as exc:  # cache failures too, so one bad source is reported once
                self.cache[key] = ("error", str(exc))
        status, value = self.cache[key]
        if status == "error":
            raise RuntimeError(value)
        return value

    def _latest(self, source, image):
        kind, _, arg = source.partition(":")
        kind = kind.strip().lower()
        arg = arg.strip()
        if kind == "github":
            return self._github(arg)
        if kind == "gitlab":
            return self._gitlab(arg)
        raise ValueError("unknown release source %r" % source)

    def _github(self, repo):
        if not re.match(r"^[\w.-]+/[\w.-]+$", repo):
            raise ValueError("github source must be github:owner/repo, got %r" % repo)
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.github_token:
            headers["Authorization"] = "Bearer " + self.github_token
        resp = http("https://api.github.com/repos/%s/releases/latest" % repo, headers=headers)
        if resp.status == 404:
            raise RuntimeError("GitHub %s has no published releases (or repo not found)" % repo)
        if resp.status in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
            raise RuntimeError("GitHub API rate limit reached (add GITHUB_TOKEN to secret.env)")
        if resp.status != 200:
            try:
                detail = resp.json().get("message", "")[:150]
            except (ValueError, AttributeError):
                detail = ""
            raise RuntimeError("GitHub API returned HTTP %s for %s %s" % (resp.status, repo, detail))
        return resp.json()["tag_name"]

    def _gitlab(self, project):
        host = "gitlab.com"
        if project.count("/") >= 2 and "." in project.split("/")[0]:
            host, project = project.split("/", 1)
        url = "https://%s/api/v4/projects/%s/releases/permalink/latest" % (
            host, urllib.parse.quote(project, safe=""))
        resp = http(url)
        if resp.status != 200:
            raise RuntimeError("GitLab API returned HTTP %s for %s" % (resp.status, project))
        return resp.json()["tag_name"]


# --------------------------------------------------------------------------
# Check 8: Docker
# --------------------------------------------------------------------------

def docker_json_lines(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def check_docker(cfg, args, secrets):
    r = CheckResult("docker", "Docker containers")
    if not shutil.which("docker"):
        return skipped(r, "Docker not installed")
    try:
        rc, out, err = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    except RuntimeError as exc:
        return skipped(r, "Docker not responding (%s)" % exc)
    if rc != 0:
        return skipped(r, "Docker installed but the daemon is not running")

    rc, out, err = run(["docker", "ps", "--no-trunc", "--format", "{{.ID}}"], timeout=60)
    if rc != 0:
        raise RuntimeError("docker ps failed: %s" % err.strip()[:300])
    ids = out.split()
    containers = []
    if ids:
        rc, out, err = run(["docker", "inspect"] + ids, timeout=120)
        if rc != 0:
            raise RuntimeError("docker inspect failed: %s" % err.strip()[:300])
        containers = json.loads(out)

    image_ids = sorted({c["Image"] for c in containers})
    images = {}
    if image_ids:
        rc, out, err = run(["docker", "image", "inspect"] + image_ids, timeout=120)
        if rc == 0:
            for img in json.loads(out):
                images[img["Id"]] = img

    registry = Registry()
    sources = ReleaseSources(registry, secrets.get("GITHUB_TOKEN"))
    digest_cache = {}
    tag_cache = {}

    def remote_digest(ref):
        key = (ref["registry"], ref["repo"], ref["tag"])
        if key not in digest_cache:
            try:
                digest_cache[key] = ("ok", registry.manifest_digest(ref["registry"], ref["repo"], ref["tag"]))
            except Exception as exc:
                digest_cache[key] = ("error", str(exc))
        status, value = digest_cache[key]
        if status == "error":
            raise RuntimeError(value)
        return value

    def remote_tags(registry_name, repo):
        key = (registry_name, repo)
        if key not in tag_cache:
            try:
                tag_cache[key] = ("ok", registry.list_tags(registry_name, repo))
            except Exception as exc:
                tag_cache[key] = ("error", str(exc))
        status, value = tag_cache[key]
        if status == "error":
            raise RuntimeError(value)
        return value

    rows, levels = [], []
    counts = {"outdated": 0, "ok": 0, "not_checked": 0, "error": 0}
    unmapped = []

    for c in sorted(containers, key=lambda c: c.get("Name", "")):
        name = c.get("Name", "").lstrip("/")
        if name in cfg.ignore_containers:
            continue
        image_str = (c.get("Config") or {}).get("Image", "") or c.get("Image", "")
        img = images.get(c.get("Image"), {})
        try:
            ref = parse_image_ref(image_str)
        except ValueError:
            ref = None
        if ref is None or re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", image_str):
            rows.append([name, image_str[:40], "-", "-", "-", "not checked: started from an image ID"])
            levels.append(None)
            counts["not_checked"] += 1
            continue

        tag = ref["tag"]
        display_tag = (tag or "latest") + ("@" + ref["digest"][7:19] if ref["digest"] else "")
        source = cfg.image_sources.get(ref["name"])
        try:
            status, latest, note = evaluate_container(cfg, ref, img, source, sources, remote_digest, remote_tags)
        except Exception as exc:
            status, latest, note = "error", "?", "check failed: %s" % exc
        if status == "not_checked" and not source:
            unmapped.append(ref["name"])
        counts[status] += 1
        rows.append([name, ref["name"], display_tag, source or "-", latest, note])
        levels.append({"outdated": "update", "error": "error"}.get(status))

    # Outdated first, then failures, then the rest (stable sort keeps names in order)
    rank = {"update": 0, "error": 1}
    order = sorted(range(len(rows)), key=lambda i: rank.get(levels[i], 2))
    rows, levels = [rows[i] for i in order], [levels[i] for i in order]
    if not containers:
        r.add_para("No running containers.")
    else:
        r.add_table(["Container", "Image", "Running tag", "Release source", "Latest", "Status"], rows, levels)

    if unmapped:
        r.add_para("Containers with a version-pinned tag are only checked if their image is in the "
                   "[docker.images] map in /etc/update-checker/config. To check these, add lines like:")
        r.add_pre("\n".join("%s = github:OWNER/REPO    # or gitlab:GROUP/PROJECT, registry, digest" % n
                            for n in sorted(set(unmapped))))

    # Reclaimable space
    try:
        rc, out, err = run(["docker", "system", "df", "--format", "{{json .}}"], timeout=180)
        if rc == 0:
            df_rows = [[d.get("Type", ""), d.get("TotalCount", ""), d.get("Active", ""),
                        d.get("Size", ""), d.get("Reclaimable", "")] for d in docker_json_lines(out)]
            r.add_para("Disk usage (docker system df):")
            r.add_table(["Type", "Total", "Active", "Size", "Reclaimable"], df_rows)
        else:
            r.add_para("docker system df failed: %s" % err.strip()[:200], "warn")
    except RuntimeError as exc:
        r.add_para("docker system df failed: %s" % exc, "warn")

    bits = ["%d running" % len(containers)]
    if counts["outdated"]:
        bits.append("%d outdated" % counts["outdated"])
        r.raise_status("update")
        r.subject.append(plural(counts["outdated"], "container") + " outdated")
    if counts["ok"]:
        bits.append("%d up to date" % counts["ok"])
    if counts["not_checked"]:
        bits.append("%d not checked" % counts["not_checked"])
    if counts["error"]:
        bits.append(plural(counts["error"], "check error"))
        r.raise_status("warn")
        r.subject.append(plural(counts["error"], "container check") + " failed")
    r.summary = ", ".join(bits)
    return r


def evaluate_container(cfg, ref, img, source, sources, remote_digest, remote_tags):
    """Return (status, latest, note) where status is one of
    outdated / ok / not_checked / error."""
    tag = ref["tag"] or "latest"
    floating = tag.lower() in cfg.floating_tags or not re.search(r"\d", tag)
    labels = ((img.get("Config") or {}).get("Labels") or {})
    label_version = labels.get("org.opencontainers.image.version")
    src_kind = (source or "").split(":", 1)[0].strip().lower()

    def digest_compare(prefix=""):
        if not ref["tag"] and ref["digest"]:
            return "not_checked", "-", prefix + "pinned by digest only, no tag to compare against"
        remote = remote_digest(dict(ref, tag=tag))
        local = set()
        for rd in img.get("RepoDigests") or []:
            try:
                lref = parse_image_ref(rd)
            except ValueError:
                continue
            if lref["name"] == ref["name"] and lref["digest"]:
                local.add(lref["digest"])
        if ref["digest"]:
            local.add(ref["digest"])
        if not local:
            return "not_checked", remote[7:19], prefix + "no registry digest for the local image (built locally?)"
        if remote in local:
            return "ok", "same digest", prefix + "up to date (digest matches %s)" % tag
        return "outdated", "new digest", prefix + "newer image pushed for '%s' - pull and recreate" % tag

    if src_kind == "digest" or (floating and src_kind in ("", "registry")):
        return digest_compare()

    if not source:
        if cfg.digest_check_unmapped:
            return digest_compare("tag re-push check only: ")
        return "not_checked", "-", "not checked (no release source configured)"

    if src_kind == "registry":
        # registry tags of this image, or of another image: registry:other/image
        target = ref
        arg = source.split(":", 1)[1].strip() if ":" in source else ""
        if arg:
            target = parse_image_ref(arg)
        tags = remote_tags(target["registry"], target["repo"])
        best = best_matching_tag(tag, tags)
        if best is None:
            return "error", "?", "no tags in registry matching the pattern of '%s'" % tag
        if tag_numbers(best) > tag_numbers(tag):
            return "outdated", best, "newer tag available"
        return "ok", best, "up to date"

    # github: / gitlab: release sources
    current = None
    if not floating:
        current = tag
    elif label_version and version_tuple(label_version):
        current = label_version
    latest = sources.latest(source, ref)
    if current is None:
        status, _, note = digest_compare("floating tag, compared digest; ")
        return status, latest, note + " (latest release %s)" % latest
    try:
        c = cmp_versions(current, latest)
    except ValueError:
        same = current.lstrip("vV") == latest.lstrip("vV")
        return ("ok" if same else "error"), latest, ("up to date" if same else
                                                     "cannot compare '%s' with '%s'" % (current, latest))
    via = "" if current == tag else " (version %s from image label)" % current
    if c < 0:
        return "outdated", latest, "update available" + via
    return "ok", latest, "up to date" + via


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------

def send_resend(api_key, sender, recipients, subject, html_body, text_body):
    payload = json.dumps({
        "from": sender, "to": recipients, "subject": subject,
        "html": html_body, "text": text_body,
    }).encode("utf-8")
    resp = http("https://api.resend.com/emails", method="POST", data=payload, headers={
        "Authorization": "Bearer " + api_key, "Content-Type": "application/json",
    }, timeout=30)
    if resp.status not in (200, 201, 202):
        detail = resp.body.decode("utf-8", "replace")[:500]
        raise RuntimeError("Resend API returned HTTP %s: %s" % (resp.status, detail))
    try:
        return resp.json().get("id")
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def build_subject(label, results):
    order = {"apt": 10, "snap": 20, "docker": 30, "pihole": 40, "reboot": 50, "disk": 60,
             "unattended_upgrades": 70, "pro": 80}
    parts = []
    for res in sorted(results, key=lambda r: order.get(r.key, 90)):
        parts.extend(res.subject)
    failed = sum(1 for r in results if r.status == "error" and not r.subject)
    if failed:
        parts.append(plural(failed, "check") + " failed")
    return "[%s] %s" % (label, ", ".join(parts) if parts else "All up to date"), not parts


def run_checks(cfg, args, secrets):
    checks = {
        "apt": lambda: check_apt(cfg, args),
        "reboot": lambda: check_reboot(cfg, args),
        "snap": lambda: check_snap(cfg, args),
        "pro": lambda: check_pro(cfg, args),
        "unattended_upgrades": lambda: check_unattended(cfg, args),
        "disk": lambda: check_disk(cfg, args),
        "pihole": lambda: check_pihole(cfg, args),
        "docker": lambda: check_docker(cfg, args, secrets),
    }
    titles = {"apt": "System packages", "reboot": "Reboot required", "snap": "Snaps", "pro": "Ubuntu Pro",
              "unattended_upgrades": "Unattended upgrades", "disk": "Disk space", "pihole": "Pi-hole",
              "docker": "Docker containers"}
    only = set(split_list(args.only)) if args.only else None
    results = []
    for key in CHECK_ORDER:
        if only is not None and key not in only:
            continue
        if not cfg.check_enabled(key):
            results.append(skipped(CheckResult(key, titles[key]), "disabled in config"))
            continue
        log("check: %s" % key)
        try:
            res = checks[key]()
        except Exception as exc:  # one failing check must not stop the others
            res = CheckResult(key, titles[key])
            res.status = "error"
            res.summary = "Check failed: %s" % exc
            res.add_para("This check could not complete: %s" % exc, "error")
            log("check %s failed: %s" % (key, exc))
        log("check: %s -> %s: %s" % (key, res.status, res.summary))
        results.append(res)
    return results


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="update-checker",
        description="Report-only update checker. Emails an HTML report via Resend.")
    p.add_argument("--dry-run", action="store_true",
                   help="run all checks and print the report instead of emailing it")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="config file (default: %(default)s)")
    p.add_argument("--secrets", default=DEFAULT_SECRETS, help="secrets file (default: %(default)s)")
    p.add_argument("--only", metavar="CHECKS",
                   help="comma-separated subset of checks to run: " + ",".join(CHECK_ORDER))
    p.add_argument("--html", metavar="FILE", help="also write the HTML report to FILE")
    p.add_argument("--skip-apt-update", action="store_true",
                   help="don't run 'apt-get update' (use the existing package lists)")
    p.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    args = p.parse_args(argv)

    if args.only:
        bad = set(split_list(args.only)) - set(CHECK_ORDER)
        if bad:
            p.error("unknown check(s): %s" % ", ".join(sorted(bad)))

    cfg = Config(args.config)
    secrets = load_secrets(args.secrets)
    if os.geteuid() != 0:
        log("warning: not running as root; apt update and some checks may fail")

    results = run_checks(cfg, args, secrets)
    subject, up_to_date = build_subject(cfg.label, results)
    text_body = render_text(cfg.label, results, subject)
    html_body = render_html(cfg.label, results, subject)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_body)
        log("HTML report written to %s" % args.html)

    if args.dry_run:
        sys.stdout.write(text_body)
        if up_to_date and not cfg.send_when_up_to_date:
            log("(dry run) everything is up to date and send_when_up_to_date = no: no email would be sent")
        return 0

    log(subject)
    if up_to_date and not cfg.send_when_up_to_date:
        log("Everything up to date and send_when_up_to_date = no; not sending email.")
        return 0
    api_key = secrets.get("RESEND_API_KEY", "")
    if not api_key or api_key.startswith("re_xxxx"):
        log("error: RESEND_API_KEY is not set in %s" % args.secrets)
        sys.stdout.write(text_body)
        return 2
    if not cfg.recipients:
        log("error: no recipient set in [general] recipient in %s" % args.config)
        sys.stdout.write(text_body)
        return 2
    sender = "%s <%s>" % (cfg.from_name, cfg.from_address) if cfg.from_name else cfg.from_address
    try:
        msg_id = send_resend(api_key, sender, cfg.recipients, subject, html_body, text_body)
    except RuntimeError as exc:
        log("error: sending email failed: %s" % exc)
        sys.stdout.write(text_body)  # keep the report in the journal
        return 1
    log("Email sent to %s (id %s)" % (", ".join(cfg.recipients), msg_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
