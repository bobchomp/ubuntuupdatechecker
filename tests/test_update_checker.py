"""Unit tests: python3 -m unittest discover -s tests"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import update_checker as u  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class Args:
    skip_apt_update = True
    only = None


def make_cfg(text):
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write(text)
    try:
        return u.Config(fh.name)
    finally:
        os.unlink(fh.name)


class ImageRefTests(unittest.TestCase):
    def test_short_name(self):
        r = u.parse_image_ref("nginx")
        self.assertEqual((r["registry"], r["repo"], r["tag"], r["digest"]),
                         ("docker.io", "library/nginx", None, None))

    def test_full(self):
        r = u.parse_image_ref("ghcr.io/immich-app/immich-server:v3.1.0@sha256:abc")
        self.assertEqual(r["name"], "ghcr.io/immich-app/immich-server")
        self.assertEqual(r["tag"], "v3.1.0")
        self.assertEqual(r["digest"], "sha256:abc")

    def test_registry_with_port(self):
        r = u.parse_image_ref("localhost:5000/team/app:1.2")
        self.assertEqual((r["registry"], r["repo"], r["tag"]), ("localhost:5000", "team/app", "1.2"))

    def test_docker_hub_user_image(self):
        r = u.parse_image_ref("docker.io/arcadiatechnology/crafty-4:4.10.8")
        self.assertEqual(r["name"], "docker.io/arcadiatechnology/crafty-4")
        self.assertEqual(u.parse_image_ref("arcadiatechnology/crafty-4")["name"], r["name"])


class VersionTests(unittest.TestCase):
    def test_cmp(self):
        self.assertEqual(u.cmp_versions("v3.1.0", "v3.2.0"), -1)
        self.assertEqual(u.cmp_versions("4.10.8", "v4.10.8"), 0)
        self.assertEqual(u.cmp_versions("1.2", "1.2.0"), 0)
        self.assertEqual(u.cmp_versions("4.0.9.2244-ls257", "v4.0.10.2544"), -1)

    def test_best_matching_tag(self):
        tags = ["latest", "v1.2.3", "v1.10.0", "v1.10.0-rc1", "1.11.0", "v1.9.9"]
        self.assertEqual(u.best_matching_tag("v1.2.3", tags), "v1.10.0")
        tags = ["4.0.9.2244-ls257", "4.0.10.2544-ls260", "4.0.10.2544-ls259", "develop"]
        self.assertEqual(u.best_matching_tag("4.0.9.2244-ls257", tags), "4.0.10.2544-ls260")
        self.assertIsNone(u.best_matching_tag("1.0", ["latest"]))


class ParserTests(unittest.TestCase):
    def test_apt_list(self):
        out = """Listing...
openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
curl/noble-updates 8.5.0-2ubuntu10.5 amd64 [upgradable from: 8.5.0-2ubuntu10.4]
libfoo/noble-infra-security 1.0+esm1 amd64 [upgradable from: 1.0]
"""
        pkgs = u.parse_apt_upgradable(out)
        self.assertEqual([p["name"] for p in pkgs], ["openssl", "curl", "libfoo"])
        self.assertEqual([p["security"] for p in pkgs], [True, False, True])
        self.assertEqual(pkgs[1]["old"], "8.5.0-2ubuntu10.4")

    def test_madison(self):
        out = (" curl | 8.5.0-2ubuntu10.6 | http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages\n"
               " curl | 8.5.0-2ubuntu10.5 | http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n")
        m = u.parse_madison(out)
        self.assertEqual(len(m["curl"]), 2)
        self.assertIn("noble-security", m["curl"][1][1])

    def test_pihole_v6(self):
        out = ("Core version is v6.1 (Latest: v6.1.2)\n"
               "Web version is v6.2.1 (Latest: v6.2.1)\n"
               "FTL version is v6.2.3 (Latest: null)\n")
        comps = u.parse_pihole_version(out)
        self.assertEqual([c["name"] for c in comps], ["Core", "Web interface", "FTL"])
        self.assertEqual(comps[0]["latest"], "v6.1.2")
        self.assertIsNone(comps[2]["latest"])

    def test_pihole_v5(self):
        out = ("  Pi-hole version is v5.18.3 (Latest: v5.18.4)\n"
               "  AdminLTE version is v5.21 (Latest: v5.21)\n"
               "  FTL version is v5.25.2 (Latest: v5.25.2)\n")
        comps = u.parse_pihole_version(out)
        self.assertEqual([c["name"] for c in comps], ["Core", "Web interface", "FTL"])

    def test_snap(self):
        out = ("Name  Version  Rev    Size   Publisher    Notes\n"
               "lxd   5.21.3   33110  94MB   canonical**  -\n")
        self.assertEqual(u.parse_snap_refresh_list(out)[0]["name"], "lxd")
        self.assertEqual(u.parse_snap_refresh_list("All snaps up to date.\n"), [])

    def test_apt_config_dump(self):
        dump = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
        self.assertEqual(u.parse_apt_config_dump(dump, "APT::Periodic::Unattended-Upgrade"), "1")
        self.assertIsNone(u.parse_apt_config_dump(dump, "APT::Periodic::Missing"))


class ConfigTests(unittest.TestCase):
    def test_examples_parse(self):
        for name in ("optiplex", "pihole", "droplet"):
            cfg = u.Config(os.path.join(ROOT, "examples", name + ".conf"))
            self.assertEqual(cfg.label, name)
            self.assertEqual(cfg.from_address, "info@rossmackenzie.co.uk")
        opt = u.Config(os.path.join(ROOT, "examples", "optiplex.conf"))
        self.assertEqual(opt.mount_points, ["/", "/mnt/storage"])
        self.assertEqual(opt.image_sources["ghcr.io/immich-app/immich-server"], "github:immich-app/immich")
        self.assertEqual(opt.image_sources["docker.io/arcadiatechnology/crafty-4"],
                         "gitlab:crafty-controller/crafty-4")
        self.assertFalse(opt.check_enabled("pihole"))
        u.Config(os.path.join(ROOT, "config", "config.example"))

    def test_defaults(self):
        cfg = make_cfg("[general]\nlabel = x\n")
        self.assertEqual(cfg.disk_warn_percent, 80)
        self.assertTrue(cfg.send_when_up_to_date)
        self.assertEqual(cfg.mount_points, ["/"])
        self.assertEqual(cfg.from_address, "info@rossmackenzie.co.uk")

    def test_secrets(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("# c\nRESEND_API_KEY='re_abc'\nexport GITHUB_TOKEN=\"t\"\n")
        try:
            with mock.patch.dict(os.environ, {}, clear=True):
                s = u.load_secrets(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(s, {"RESEND_API_KEY": "re_abc", "GITHUB_TOKEN": "t"})


class SubjectTests(unittest.TestCase):
    def test_subject(self):
        a = u.CheckResult("apt", "System packages")
        a.subject = ["12 updates (3 security)"]
        d = u.CheckResult("docker", "Docker")
        d.subject = ["2 containers outdated"]
        r = u.CheckResult("reboot", "Reboot")
        r.subject = ["reboot needed"]
        subject, up = u.build_subject("optiplex", [a, r, d])
        self.assertEqual(subject, "[optiplex] 12 updates (3 security), 2 containers outdated, reboot needed")
        self.assertFalse(up)

    def test_all_up_to_date(self):
        subject, up = u.build_subject("pihole", [u.CheckResult("apt", "x")])
        self.assertEqual(subject, "[pihole] All up to date")
        self.assertTrue(up)

    def test_failed_check_in_subject(self):
        bad = u.CheckResult("snap", "Snaps")
        bad.status = "error"
        subject, up = u.build_subject("x", [bad])
        self.assertEqual(subject, "[x] 1 check failed")
        self.assertFalse(up)


class ResilienceTests(unittest.TestCase):
    def test_failing_check_does_not_stop_others(self):
        cfg = make_cfg("[general]\nlabel = t\n")
        with mock.patch.object(u, "check_snap", side_effect=RuntimeError("boom")), \
                mock.patch.object(u, "check_apt", side_effect=RuntimeError("apt down")):
            args = Args()
            args.only = "apt,snap,reboot,disk"
            results = u.run_checks(cfg, args, {})
        status = {r.key: r.status for r in results}
        self.assertEqual(status["apt"], "error")
        self.assertEqual(status["snap"], "error")
        self.assertIn(status["reboot"], ("ok", "alert"))
        self.assertIn("disk", status)
        # both renderers cope with every block type
        subject, _ = u.build_subject("t", results)
        self.assertIn("2 checks failed", subject)
        self.assertIn("boom", u.render_text("t", results, subject))
        self.assertIn("apt down", u.render_html("t", results, subject))


# ---------------------------------------------------------------- Docker

IMG = {
    "sha256:immich": {"Id": "sha256:immich", "RepoDigests": ["ghcr.io/immich-app/immich-server@sha256:i1"],
                      "Config": {"Labels": {}}},
    "sha256:crafty": {"Id": "sha256:crafty",
                      "RepoDigests": ["registry.gitlab.com/crafty-controller/crafty-4@sha256:c1"],
                      "Config": {"Labels": {}}},
    "sha256:nginx": {"Id": "sha256:nginx", "RepoDigests": ["nginx@sha256:old"], "Config": {"Labels": {}}},
    "sha256:redis": {"Id": "sha256:redis", "RepoDigests": ["redis@sha256:r1"], "Config": {"Labels": {}}},
    "sha256:pg": {"Id": "sha256:pg", "RepoDigests": ["postgres@sha256:p1"], "Config": {"Labels": {}}},
    "sha256:jelly": {"Id": "sha256:jelly", "RepoDigests": ["jellyfin/jellyfin@sha256:j1"],
                     "Config": {"Labels": {"org.opencontainers.image.version": "10.9.0"}}},
    "sha256:sonarr": {"Id": "sha256:sonarr", "RepoDigests": ["lscr.io/linuxserver/sonarr@sha256:s1"],
                      "Config": {"Labels": {}}},
    "sha256:broken": {"Id": "sha256:broken", "RepoDigests": ["ghcr.io/x/broken@sha256:b"],
                      "Config": {"Labels": {}}},
}
CONTAINERS = [
    ("immich_server", "ghcr.io/immich-app/immich-server:v3.1.0@sha256:i1", "sha256:immich"),
    ("crafty", "registry.gitlab.com/crafty-controller/crafty-4:4.11.0", "sha256:crafty"),
    ("web", "nginx:latest", "sha256:nginx"),
    ("cache", "redis:7.2.4", "sha256:redis"),
    ("db", "postgres:16-alpine", "sha256:pg"),
    ("jellyfin", "jellyfin/jellyfin:latest", "sha256:jelly"),
    ("sonarr", "lscr.io/linuxserver/sonarr:4.0.9.2244-ls257", "sha256:sonarr"),
    ("broken", "ghcr.io/x/broken:latest", "sha256:broken"),
]
REMOTE_DIGESTS = {("docker.io", "library/nginx", "latest"): "sha256:new",
                  ("docker.io", "library/postgres", "16-alpine"): "sha256:p1"}
REMOTE_TAGS = {("lscr.io", "linuxserver/sonarr"): ["latest", "4.0.9.2244-ls257", "4.0.10.2544-ls260"]}
RELEASES = {"github:immich-app/immich": "v3.2.0", "gitlab:crafty-controller/crafty-4": "v4.11.0",
            "github:jellyfin/jellyfin": "v10.10.1"}


def fake_run(cmd, timeout=120, env_extra=None):
    if cmd[:2] == ["docker", "info"]:
        return 0, "27.0.0\n", ""
    if cmd[:2] == ["docker", "ps"]:
        return 0, "\n".join(c[0] for c in CONTAINERS) + "\n", ""
    if cmd[:2] == ["docker", "inspect"]:
        data = [{"Name": "/" + n, "Image": i, "Config": {"Image": ref}} for n, ref, i in CONTAINERS if n in cmd]
        return 0, json.dumps(data), ""
    if cmd[:3] == ["docker", "image", "inspect"]:
        return 0, json.dumps([IMG[i] for i in cmd[3:]]), ""
    if cmd[:3] == ["docker", "system", "df"]:
        return 0, ('{"Type":"Images","TotalCount":"9","Active":"8","Size":"5GB","Reclaimable":"1GB (20%)"}\n'
                   '{"Type":"Build Cache","TotalCount":"0","Active":"0","Size":"0B","Reclaimable":"0B"}\n'), ""
    raise AssertionError(cmd)


def fake_digest(self, registry, repo, tag):
    if repo == "x/broken":
        raise RuntimeError("ghcr.io: connection refused")
    return REMOTE_DIGESTS[(registry, repo, tag)]


class DockerTests(unittest.TestCase):
    CFG = """[general]
label = t
[docker.images]
ghcr.io/immich-app/immich-server = github:immich-app/immich
registry.gitlab.com/crafty-controller/crafty-4 = gitlab:crafty-controller/crafty-4
postgres = digest
jellyfin/jellyfin = github:jellyfin/jellyfin
lscr.io/linuxserver/sonarr = registry
"""

    def run_docker(self, cfg_text=CFG):
        cfg = make_cfg(cfg_text)
        with mock.patch.object(u.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(u, "run", side_effect=fake_run), \
                mock.patch.object(u.Registry, "_load_docker_auths", return_value={}), \
                mock.patch.object(u.Registry, "manifest_digest", fake_digest), \
                mock.patch.object(u.Registry, "list_tags", lambda s, reg, repo: REMOTE_TAGS[(reg, repo)]), \
                mock.patch.object(u.ReleaseSources, "_latest", lambda s, src: RELEASES[src]):
            return u.check_docker(cfg, Args(), {})

    def test_statuses(self):
        r = self.run_docker()
        table = [b for b in r.blocks if b[0] == "table"][0]
        rows = {row[0]: row for row in table[2]}
        self.assertIn("update available", rows["immich_server"][5])     # v3.1.0 < v3.2.0
        self.assertEqual(rows["immich_server"][2], "v3.1.0@i1")
        self.assertEqual(rows["crafty"][5], "up to date")                # 4.11.0 == v4.11.0
        self.assertIn("newer image pushed", rows["web"][5])              # floating, digest differs
        self.assertIn("not checked", rows["cache"][5])                   # pinned, not in map
        self.assertIn("up to date (digest", rows["db"][5])               # "digest" source, same digest
        self.assertIn("update available", rows["jellyfin"][5])           # version from OCI label
        self.assertIn("10.9.0", rows["jellyfin"][5])
        self.assertEqual(rows["sonarr"][4], "4.0.10.2544-ls260")         # registry tag compare
        self.assertIn("check failed", rows["broken"][5])                 # registry unreachable
        self.assertEqual(r.subject, ["4 containers outdated", "1 container check failed"])
        self.assertIn("1 not checked", r.summary)
        # unmapped hint names the exact key to add
        pre = [b for b in r.blocks if b[0] == "pre"][0][1]
        self.assertIn("docker.io/library/redis = ", pre)
        # docker system df table is present
        self.assertTrue(any(b[0] == "table" and b[1][0] == "Type" for b in r.blocks))

    def test_digest_check_unmapped(self):
        REMOTE_DIGESTS[("docker.io", "library/redis", "7.2.4")] = "sha256:r1"
        try:
            r = self.run_docker(self.CFG.replace("[docker.images]",
                                                 "[docker]\ndigest_check_unmapped = yes\n[docker.images]"))
        finally:
            del REMOTE_DIGESTS[("docker.io", "library/redis", "7.2.4")]
        rows = {row[0]: row for row in r.blocks[0][2]}
        self.assertIn("tag re-push check only", rows["cache"][5])

    def test_docker_not_running(self):
        cfg = make_cfg("[general]\nlabel = t\n")
        with mock.patch.object(u.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(u, "run", return_value=(1, "", "Cannot connect")):
            r = u.check_docker(cfg, Args(), {})
        self.assertEqual(r.status, "skipped")


# ---------------------------------------------------------------- Apps

TS_REPO = "https://pkgs.tailscale.com/stable/ubuntu noble/main amd64 Packages"
DO_MIRROR = "http://mirrors.digitalocean.com/ubuntu noble/universe amd64 Packages"

GLOBAL_POLICY = """Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 %s
     release o=Tailscale,a=noble,n=noble,l=Tailscale,c=main,b=amd64
     origin pkgs.tailscale.com
 500 %s
     release v=24.04,o=Ubuntu,a=noble,n=noble,l=Ubuntu,c=universe,b=amd64
     origin mirrors.digitalocean.com
 510 https://esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages
     release v=24.04,o=UbuntuESMApps,a=noble-apps-security,n=noble,l=UbuntuESMApps,c=main,b=amd64
     origin esm.ubuntu.com
Pinned packages:
     tailscale -> 1.76.6 with priority 1001
""" % (TS_REPO, DO_MIRROR)

POLICY_REPO_NEWER = """tailscale:
  Installed: 1.76.6
  Candidate: 1.78.1
  Version table:
     1.78.1 500
        500 %s
 *** 1.76.6 100
        100 /var/lib/dpkg/status
""" % TS_REPO
POLICY_REPO_SAME = """tailscale:
  Installed: 1.76.6
  Candidate: 1.76.6
  Version table:
 *** 1.76.6 500
        500 %s
        100 /var/lib/dpkg/status
""" % TS_REPO
POLICY_LOCAL_ONLY = """cloudflared:
  Installed: 2024.10.1
  Candidate: 2024.10.1
  Version table:
 *** 2024.10.1 100
        100 /var/lib/dpkg/status
"""
POLICY_UBUNTU = """rclone:
  Installed: 1.60.1+dfsg-3ubuntu0.24.04.1
  Candidate: 1.60.1+dfsg-3ubuntu0.24.04.1
  Version table:
 *** 1.60.1+dfsg-3ubuntu0.24.04.1 500
        500 %s
        100 /var/lib/dpkg/status
""" % DO_MIRROR

APT_INSTALLED = """Listing...
cloudflared/now 2024.10.1 amd64 [installed,local]
libpython3.11/now 3.11.17-1+noble1 amd64 [installed,local]
libpython3.11-dev/now 3.11.17-1+noble1 amd64 [installed,local]
linux-image-6.8.0-40-generic/now 6.8.0-40.40 amd64 [installed,local]
oldtool/now 0.3 all [installed,automatic,local]
zlib1g/noble-updates,now 1:1.3.dfsg-3.1ubuntu2.3 amd64 [installed]
"""
# binary package -> (source package, version)
LOCAL_DB = {"cloudflared": ("cloudflared", "2024.10.1"),
            "libpython3.11": ("python3.11", "3.11.17-1+noble1"),
            "libpython3.11-dev": ("python3.11", "3.11.17-1+noble1"),
            "linux-image-6.8.0-40-generic": ("linux-signed", "6.8.0-40.40"),
            "oldtool": ("oldtool", "0.3")}


class AppsEnv:
    """Fake machine for check_apps: dpkg packages, apt policies, binaries."""

    def __init__(self, dpkg=None, policies=None, binaries=None, apt_installed="Listing...\n"):
        self.dpkg = dpkg or {}                  # package -> version
        self.policies = policies or {}          # package -> apt-cache policy text
        self.binaries = binaries or {}          # name -> callable(argv) -> (rc, out, err)
        self.apt_installed = apt_installed
        self.ran = []

    def which(self, name):
        if name in ("apt", "apt-cache"):
            return "/usr/bin/" + name
        return "/usr/local/bin/" + name if name in self.binaries else None

    def run(self, cmd, timeout=120, env_extra=None):
        self.ran.append(cmd)
        if cmd == ["apt-cache", "policy"]:
            return 0, GLOBAL_POLICY, ""
        if cmd[:2] == ["apt-cache", "policy"]:
            return 0, self.policies[cmd[2]], ""
        if cmd == ["apt", "list", "--installed"]:
            return 0, self.apt_installed, ""
        if cmd[0] == "dpkg-query" and cmd[2].startswith("-f=${Status}"):
            if cmd[3] in self.dpkg:
                return 0, "install ok installed\t%s" % self.dpkg[cmd[3]], ""
            return 1, "", "no packages found"
        if cmd[0] == "dpkg-query":
            return 0, "".join("%s:amd64\t%s\t%s\t%s\n" % (n, n, LOCAL_DB[n][0], LOCAL_DB[n][1])
                              for n in cmd[3:]), ""
        if cmd[:2] == ["dpkg", "--compare-versions"]:
            return (0 if u.cmp_versions(cmd[2], cmd[4]) > 0 else 1), "", ""
        name = os.path.basename(cmd[0])
        if name in self.binaries:
            return self.binaries[name](cmd)
        raise AssertionError(cmd)


def run_apps(cfg_text, env, releases):
    cfg = make_cfg(cfg_text)
    with mock.patch.object(u, "run", side_effect=env.run), \
            mock.patch.object(u.shutil, "which", side_effect=env.which), \
            mock.patch.object(u.os.path, "exists", return_value=True), \
            mock.patch.object(u.ReleaseSources, "_latest", lambda s, src: releases[src]):
        r = u.check_apps(cfg, Args(), {})
    table = [b for b in r.blocks if b[0] == "table"]
    rows = {row[0]: row for row in table[0][2]} if table else {}
    return r, rows


class AppsParserTests(unittest.TestCase):
    def test_parse_apt_policy(self):
        self.assertEqual(u.parse_apt_policy(POLICY_REPO_NEWER), ("1.76.6", "1.78.1", [TS_REPO]))
        self.assertEqual(u.parse_apt_policy(POLICY_LOCAL_ONLY), ("2024.10.1", "2024.10.1", []))

    def test_parse_ubuntu_sources(self):
        srcs = u.parse_ubuntu_sources(GLOBAL_POLICY)
        self.assertIn(DO_MIRROR, srcs)                     # Ubuntu, via a cloud mirror
        self.assertTrue(any("esm.ubuntu.com" in x for x in srcs))
        self.assertNotIn(TS_REPO, srcs)                    # third-party repo

    def test_parse_local_packages(self):
        self.assertEqual(u.parse_local_packages(APT_INSTALLED),
                         ["cloudflared", "libpython3.11", "libpython3.11-dev",
                          "linux-image-6.8.0-40-generic", "oldtool"])

    def test_extract_version(self):
        self.assertEqual(u.extract_version("cloudflared version 2024.10.1 (built 2024-10-02-1234 UTC)"),
                         "2024.10.1")
        self.assertEqual(u.extract_version("1.76.6\n  go version: go1.23.1"), "1.76.6")
        self.assertIsNone(u.extract_version("no digits"))

    def test_config(self):
        cfg = make_cfg("[apps]\nauto_detect = no\nignore = oldtool, rclone\n"
                       "myapp = gitlab:me/myapp | /opt/myapp/bin/myapp --version\n")
        self.assertFalse(cfg.apps_auto_detect)
        self.assertEqual(cfg.apps_ignore, {"oldtool", "rclone"})
        self.assertEqual(cfg.apps, {"myapp": ("gitlab:me/myapp", "/opt/myapp/bin/myapp --version")})
        self.assertTrue(make_cfg("[general]\n").apps_auto_detect)    # on by default, no [apps] needed
        for name in ("optiplex", "pihole", "droplet"):
            u.Config(os.path.join(ROOT, "examples", name + ".conf"))


class AppsCheckTests(unittest.TestCase):
    def test_auto_detect_with_no_config(self):
        env = AppsEnv(
            dpkg={"tailscale": "1.76.6", "cloudflared": "2024.10.1", "rclone": "1.60.1+dfsg-3ubuntu0.24.04.1"},
            policies={"tailscale": POLICY_REPO_NEWER, "cloudflared": POLICY_LOCAL_ONLY, "rclone": POLICY_UBUNTU},
            binaries={"restic": lambda cmd: (0, "restic 0.17.1 compiled with go1.23\n", "")},
            apt_installed=APT_INSTALLED)
        r, rows = run_apps("[general]\nlabel = pihole\n", env,
                           {"github:tailscale/tailscale": "v1.78.1", "github:cloudflare/cloudflared": "2025.10.0",
                            "github:restic/restic": "v0.17.1"})
        # Tailscale from its apt repo: shown, but apt already counts it
        self.assertIn("via apt", rows["tailscale"][4])
        self.assertIn("apt repo, auto-detected", rows["tailscale"][3])
        # cloudflared from a downloaded .deb: apt never updates it -> counted
        self.assertIn("installed manually", rows["cloudflared"][4])
        self.assertIn("manual .deb", rows["cloudflared"][3])
        # restic as a plain binary, read with its known version command
        self.assertEqual(rows["restic"][4], "up to date")
        self.assertIn(["/usr/local/bin/restic", "version"], env.ran)
        # Ubuntu's own rclone package: left to the System packages check
        self.assertNotIn("rclone", rows)
        # other packages apt can't update: grouped, kernel left out, cloudflared not repeated
        self.assertIn("python3.11 (libpython3.11, libpython3.11-dev)", rows)
        self.assertIn("not checked", rows["python3.11 (libpython3.11, libpython3.11-dev)"][4])
        self.assertIn("oldtool", rows)
        self.assertFalse(any(k.startswith("linux") for k in rows))
        self.assertEqual(sum(1 for k in rows if k.startswith("cloudflared")), 1)
        self.assertEqual(r.subject, ["1 app update"])
        self.assertIn("2 not checked", r.summary)
        hint = [b[1] for b in r.blocks if b[0] == "pre"][0]
        self.assertIn("python3.11 = github:OWNER/REPO", hint)
        self.assertIn("ignore = oldtool, python3.11", hint)
        # never asked tailscale/cloudflared (dpkg-installed) to run at all
        self.assertFalse(any(os.path.basename(c[0]) in ("tailscale", "cloudflared") for c in env.ran))

    def test_released_but_not_in_apt_repo_yet(self):
        env = AppsEnv(dpkg={"tailscale": "1.76.6"}, policies={"tailscale": POLICY_REPO_SAME})
        r, rows = run_apps("[general]\n", env, {"github:tailscale/tailscale": "v1.78.1"})
        self.assertIn("not yet in the apt repo", rows["tailscale"][4])
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.subject, [])

    def test_configured_apps_and_ignore(self):
        env = AppsEnv(
            dpkg={"broken": "1.0"}, policies={"broken": POLICY_LOCAL_ONLY},
            binaries={"mytool": lambda cmd: (0, "mytool 3.2.1\n", ""),
                      "odd": lambda cmd: (0, "odd v0.9\n", ""),
                      "cloudflared": lambda cmd: (0, "cloudflared version 2025.10.0 (built x)\n", "")},
            apt_installed=APT_INSTALLED)
        r, rows = run_apps(
            "[apps]\nignore = oldtool, python3.11\nmytool = github:me/mytool\n"
            "odd = gitlab:me/odd | /srv/odd/bin/odd --print-version\nghost = github:me/ghost\n"
            "broken = github:me/broken\n",
            env, {"github:me/mytool": "v3.2.1", "gitlab:me/odd": "v1.0", "github:me/broken": "x",
                  "github:cloudflare/cloudflared": "2025.10.0"})
        self.assertEqual(rows["mytool"][4], "up to date")
        self.assertIn(["/usr/local/bin/mytool", "--version"], env.ran)   # only --version is guessed
        self.assertEqual(rows["odd"][1], "0.9")                          # configured command
        self.assertIn(["/srv/odd/bin/odd", "--print-version"], env.ran)
        self.assertIn("not installed", rows["ghost"][4])
        self.assertIn("cannot compare", rows["broken"][4])
        self.assertEqual(rows["cloudflared"][4], "up to date")           # binary, auto-detected
        self.assertNotIn("oldtool", rows)                                # ignored
        self.assertFalse(any(k.startswith("python3.11") for k in rows))  # ignored by source name
        self.assertEqual(r.subject, ["1 app update", "1 app check failed"])

    def test_configured_known_app_reuses_known_command(self):
        env = AppsEnv(binaries={"tailscale": lambda cmd: (0, "1.78.1\n  go version: go1.23\n", "")})
        r, rows = run_apps("[apps]\ntailscale = github:tailscale/tailscale\n", env,
                           {"github:tailscale/tailscale": "v1.78.1"})
        self.assertEqual(rows["tailscale"][4], "up to date")
        self.assertIn(["/usr/local/bin/tailscale", "version"], env.ran)
        self.assertNotIn(["/usr/local/bin/tailscale", "--version"], env.ran)

    def test_unreadable_version_suggests_command(self):
        env = AppsEnv(binaries={"weird": lambda cmd: (2, "", "flag provided but not defined: -version")})
        r, rows = run_apps("[apps]\nweird = github:me/weird\n", env, {})
        self.assertIn("weird = SOURCE | weird -v", rows["weird"][4])
        self.assertEqual(len([c for c in env.ran if "weird" in c[0]]), 1)   # tried --version only

    def test_release_lookup_failure(self):
        def boom(s, src):
            raise RuntimeError("GitHub API rate limit reached")
        env = AppsEnv(dpkg={"cloudflared": "2024.10.1"}, policies={"cloudflared": POLICY_LOCAL_ONLY})
        cfg = make_cfg("[general]\n")
        with mock.patch.object(u, "run", side_effect=env.run), \
                mock.patch.object(u.shutil, "which", side_effect=env.which), \
                mock.patch.object(u.ReleaseSources, "_latest", boom):
            r = u.check_apps(cfg, Args(), {})
        self.assertEqual(r.status, "warn")
        self.assertIn("rate limit", r.blocks[0][2][0][4])
        self.assertEqual(r.subject, ["1 app check failed"])

    def test_nothing_found(self):
        r, rows = run_apps("[general]\n", AppsEnv(), {})
        self.assertEqual(r.status, "ok")
        self.assertEqual(r.summary, "No third-party apps found")

    def test_auto_detect_off_and_nothing_listed(self):
        r = u.check_apps(make_cfg("[apps]\nauto_detect = no\n"), Args(), {})
        self.assertEqual(r.status, "skipped")


class MainEmailTests(unittest.TestCase):
    """Every run emails the report, however it was started."""

    def run_main(self, argv, cfg_text="[general]\nlabel = pihole\nrecipient = me@example.com\n",
                 secrets="RESEND_API_KEY=re_test\n", env=None, up_to_date=True):
        res = u.CheckResult("apt", "System packages")
        res.summary = "All packages up to date"
        if not up_to_date:
            res.subject = ["3 updates"]
        with tempfile.TemporaryDirectory() as d:
            conf, sec = os.path.join(d, "config"), os.path.join(d, "secret.env")
            with open(conf, "w") as fh:
                fh.write(cfg_text)
            with open(sec, "w") as fh:
                fh.write(secrets)
            out = mock.MagicMock()
            with mock.patch.object(u, "run_checks", return_value=[res]), \
                    mock.patch.object(u, "send_resend", return_value="id1") as send, \
                    mock.patch.object(u.sys, "stdout", out), \
                    mock.patch.dict(os.environ, env or {}, clear=True):
                rc = u.main(argv + ["--config", conf, "--secrets", sec])
        printed = "".join(c.args[0] for c in out.write.call_args_list)
        return rc, send, printed

    def test_plain_run_emails(self):
        rc, send, printed = self.run_main([])
        self.assertEqual(rc, 0)
        send.assert_called_once()
        self.assertEqual(printed, "")
        subject, html, text = send.call_args.args[3], send.call_args.args[4], send.call_args.args[5]
        self.assertEqual(subject, "[pihole] All up to date")
        self.assertIn("Started by command: update-checker --config", text)
        self.assertIn("Started by command", html)

    def test_dry_run_prints_and_emails(self):
        rc, send, printed = self.run_main(["--dry-run"])
        self.assertEqual(rc, 0)
        send.assert_called_once()
        self.assertIn("Subject: [pihole] All up to date", printed)
        self.assertIn("update-checker --dry-run", printed)

    def test_no_email(self):
        rc, send, printed = self.run_main(["--no-email"])
        self.assertEqual(rc, 0)
        send.assert_not_called()
        self.assertIn("Subject: [pihole]", printed)

    def test_partial_run_marked_in_subject(self):
        rc, send, _ = self.run_main(["--only", "docker,apt"], up_to_date=False)
        self.assertEqual(send.call_args.args[3], "[pihole] (apt, docker only) 3 updates")

    def test_scheduled_run(self):
        rc, send, _ = self.run_main([], env={"INVOCATION_ID": "abc"})
        self.assertIn("Scheduled run (update-checker.service)", send.call_args.args[5])

    def test_missing_key_prints_report_once(self):
        rc, send, printed = self.run_main(["--dry-run"], secrets="")
        self.assertEqual(rc, 2)
        send.assert_not_called()
        self.assertEqual(printed.count("Subject: [pihole]"), 1)

    def test_send_failure_keeps_report(self):
        with mock.patch.object(u, "send_resend", side_effect=RuntimeError("HTTP 500")):
            res = u.CheckResult("apt", "x")
            with tempfile.TemporaryDirectory() as d:
                conf, sec = os.path.join(d, "c"), os.path.join(d, "s")
                open(conf, "w").write("[general]\nrecipient = a@b.c\n")
                open(sec, "w").write("RESEND_API_KEY=re_k\n")
                out = mock.MagicMock()
                with mock.patch.object(u, "run_checks", return_value=[res]), \
                        mock.patch.object(u.sys, "stdout", out), mock.patch.dict(os.environ, {}, clear=True):
                    rc = u.main(["--config", conf, "--secrets", sec])
        self.assertEqual(rc, 1)
        self.assertIn("Subject:", "".join(c.args[0] for c in out.write.call_args_list))

    def test_send_when_up_to_date_no_is_still_honoured(self):
        rc, send, _ = self.run_main([], cfg_text="[general]\nrecipient = a@b.c\nsend_when_up_to_date = no\n")
        send.assert_not_called()
        rc, send, _ = self.run_main([], cfg_text="[general]\nrecipient = a@b.c\nsend_when_up_to_date = no\n",
                                    up_to_date=False)
        send.assert_called_once()

    def test_examples_email_every_run(self):
        for name in ("optiplex", "pihole", "droplet"):
            self.assertTrue(u.Config(os.path.join(ROOT, "examples", name + ".conf")).send_when_up_to_date)


class EmailTests(unittest.TestCase):
    def test_resend_payload(self):
        captured = {}

        def fake_http(url, method="GET", headers=None, data=None, timeout=None):
            captured.update(url=url, method=method, headers=headers, data=json.loads(data))
            return u.HTTPResult(200, {}, b'{"id":"abc"}')

        with mock.patch.object(u, "http", side_effect=fake_http):
            msg_id = u.send_resend("re_k", "Update Checker <info@rossmackenzie.co.uk>", ["a@b.c"],
                                   "[x] All up to date", "<p>hi</p>", "hi")
        self.assertEqual(msg_id, "abc")
        self.assertEqual(captured["url"], "https://api.resend.com/emails")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer re_k")
        self.assertEqual(captured["data"]["to"], ["a@b.c"])

    def test_resend_error(self):
        with mock.patch.object(u, "http", return_value=u.HTTPResult(403, {}, b'{"message":"bad"}')):
            with self.assertRaises(RuntimeError):
                u.send_resend("re_k", "x@y.z", ["a@b.c"], "s", "h", "t")


if __name__ == "__main__":
    unittest.main()
