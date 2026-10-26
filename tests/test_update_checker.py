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
                mock.patch.object(u.ReleaseSources, "_latest", lambda s, src, img: RELEASES[src]):
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
