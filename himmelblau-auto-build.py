#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Himmelblau autobuilder/publisher (per-distro DEB/RPM repos)
with bootstrap + missing-distro retries

- Repo: ~/code/himmelblau (override with --repo-dir)
- Artifacts: <repo>/packaging/ (DEBs, RPMs, optional SBOMs)
- Publishes:
    stable/<tag>/deb/<distro>/*.deb  + Packages/Release
    stable/<tag>/rpm/<distro>/*.rpm  + repodata/
    nightly/<YYYY-MM-DD>-<commit>/(deb|rpm)/<distro>/...
    .../sbom/
- Bootstrap: if stable/nightly not yet present in --publish-dir, build
  & publish the latest stable tag (reachable from stable-2.x)
  and a nightly from main.
- Optional APT Release signing if HBL_GPG_KEYID is set.
- On every run, before planning new builds, we:
  * Parse 'Per-distro' targets from origin/main:Makefile
  * Detect missing distros in stable/<latest_tag> and nightly/<latest_label>
  * Rebuild ONLY those missing distros (make <target>)
    and publish incrementally
"""

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from packaging import version
import tempfile

DEFAULT_REPO_DIR = Path.home() / "code" / "himmelblau"
DEFAULT_PUBLISH_DIR = Path("/srv/repos/himmelblau")
SUPPORTED_BRANCHES = ["stable-3.x"]
STATE_FILE = ".build_state.json"
LOCK_FILE = ".build_lock"
PACKAGING_DIR = "packaging"

STABLE_TAG_RE = re.compile(
    r'^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
)
NIGHTLY_LABEL_RE = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})-[0-9a-f]+$'
)

DEB_RE = re.compile(
    r"""(?xi)^.*(?P<ver>\d+\.\d+\.\d+)-(?P<distro>[a-z0-9.]+)(?:~[0-9a-z]+)?_(?P<arch>amd64|arm64)\.deb$"""
)
RPM_RE = re.compile(
    r"""(?xi).*\. (?P<arch>x86_64|aarch64|noarch) - (?P<distro>fedora\d+|rawhide|rocky\d+|leap\d(?:\.\d)?|tumbleweed|sle\d+sp\d+|sle\d{2}|amzn\d+) \.rpm$"""
)

GPG_KEYID = os.environ.get("HBL_GPG_KEYID")
GPG_HOMEDIR = os.environ.get("HBL_GPG_HOMEDIR")
GPG_EXTRA = os.environ.get("HBL_GPG_EXTRA", "")


def log(msg: str):
    print(f"[{dt.datetime.now().isoformat(timespec='seconds')}] {msg}",
          flush=True)


# Log file switching for separate stable/nightly logs
_original_stdout = None
_original_stderr = None
_current_log_file = None


def switch_log(path: Optional[Path]):
    """Switch stdout/stderr to the specified log file,
    or restore to original if None."""
    global _original_stdout, _original_stderr, _current_log_file

    # Save original streams on first call
    if _original_stdout is None:
        _original_stdout = sys.stdout
        _original_stderr = sys.stderr

    # Close current log file if open (and not one of the originals)
    if _current_log_file is not None:
        try:
            _current_log_file.close()
        except Exception:
            pass
        _current_log_file = None

    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        _current_log_file = open(path, "a", buffering=1)
        sys.stdout = _current_log_file
        sys.stderr = _current_log_file
    else:
        sys.stdout = _original_stdout
        sys.stderr = _original_stderr


def run(cmd, cwd: Optional[Path] = None, check=True, capture=False, env=None):
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env
    )


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def utc_today() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%d")


def load_state(path: Path) -> Dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            path.rename(path.with_suffix(".corrupt.bak"))
    return {"built_tags": {}, "nightly": {}}


def save_state(path: Path, state: Dict):
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd = None

    def acquire(self):
        import fcntl
        self.fd = open(self.path, "w")
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.fd.write(str(os.getpid()))
        self.fd.flush()

    def release(self):
        if self.fd:
            import fcntl
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                self.fd.close()


# --- Git ops ---
def git_fetch_all(repo: Path):
    log("Fetching origin (branches + tags)...")
    run(["git", "fetch", "--all", "--tags", "--prune"], cwd=repo)


def git_list_tags(repo: Path) -> List[str]:
    res = run(["git", "tag", "--list"], cwd=repo, capture=True)
    return [t.strip() for t in res.stdout.decode().splitlines() if t.strip()]


def tag_on_branch(repo: Path, tag: str, branch: str) -> bool:
    try:
        run(["git", "merge-base", "--is-ancestor", tag, f"origin/{branch}"],
            cwd=repo)
        return True
    except subprocess.CalledProcessError:
        return False


def git_rev_parse(repo: Path, ref: str) -> str:
    res = run(["git", "rev-parse", ref], cwd=repo, capture=True)
    return res.stdout.decode().strip()


def git_show(repo: Path, ref_and_path: str) -> Optional[str]:
    try:
        res = run(["git", "show", ref_and_path], cwd=repo, capture=True)
        return res.stdout.decode()
    except subprocess.CalledProcessError:
        return None


def clean_target_packages(repo: Path):
    """
    Remove stray *.deb files inside target/<distro>/debian/
    and stray *.rpm files inside target/<distro>/generate-rpm/,
    without deleting the directories themselves.
    """
    target_root = repo / "target"
    if not target_root.exists():
        return

    for distro_dir in target_root.iterdir():
        if not distro_dir.is_dir():
            continue

        # Debian packages: target/<distro>/debian/*.deb
        debian_dir = distro_dir / "debian"
        if debian_dir.is_dir():
            for deb in debian_dir.glob("*.deb"):
                try:
                    deb.unlink()
                except Exception:
                    pass

        # RPM packages: target/<distro>/generate-rpm/*.rpm
        genrpm_dir = distro_dir / "generate-rpm"
        if genrpm_dir.is_dir():
            for rpm in genrpm_dir.glob("*.rpm"):
                try:
                    rpm.unlink()
                except Exception:
                    pass


def checkout_clean(repo: Path, ref: str):
    log(f"Checking out {ref}...")
    run(["git", "checkout", "--force", ref], cwd=repo)
    run(["git", "reset", "--hard"], cwd=repo)
    run(["git", "clean", "-fdx", "-e", "target"], cwd=repo)
    clean_target_packages(repo)


# --- Build & collect ---
def make_package(repo: Path, env: Optional[dict]) -> int:
    log("Running: make package")
    try:
        run(["/usr/bin/make", "package"], cwd=repo, env=env)
        return 0
    except subprocess.CalledProcessError as e:
        return e.returncode


def make_arm64(repo: Path, env: Optional[dict]) -> int:
    log("Running: make arm64")
    try:
        run(["/usr/bin/make", "arm64"], cwd=repo, env=env)
        return 0
    except subprocess.CalledProcessError as e:
        return e.returncode


def make_target(repo: Path, target: str, env: Optional[dict]) -> int:
    try:
        log(f"Running: make {target}")
        run(["/usr/bin/make", target], cwd=repo, env=env)
        return 0
    except subprocess.CalledProcessError as e:
        log(f"WARN: make {target} failed with rc={e.returncode} (continuing)")
        return e.returncode


def parse_artifact(p: Path) -> Tuple[str, Optional[str]]:
    nl = p.name.lower()
    if nl.endswith(".deb"):
        m = DEB_RE.match(nl)
        if m:
            distro = m.group("distro")
            arch = m.group("arch")
            # arm64 packages go to a separate "<distro>-arm64" directory
            # to avoid mixed-arch Packages files.
            # amd64 (and future additional primary-arch) packages use
            # the plain "<distro>" directory, preserving existing repo URLs.
            if arch == "arm64":
                return ("deb", f"{distro}-arm64")
            return ("deb", distro)
        return ("deb", "unknown")
    if nl.endswith(".rpm"):
        m = RPM_RE.match(nl)
        if m:
            distro = m.group("distro")
            arch = m.group("arch")
            # aarch64 packages go to a separate "<distro>-aarch64" directory
            # to avoid mixed-arch repos. noarch and x86_64 (primary-arch)
            # packages use the plain "<distro>" directory, preserving
            # existing repo URLs.
            if arch == "aarch64":
                return ("rpm", f"{distro}-aarch64")
            return ("rpm", distro)
        return ("rpm", "unknown")
    if nl.endswith((".spdx", "sbom.json", ".cdx.json", ".spdx.json")):
        return ("sbom", None)
    return ("other", None)


def collect_from_packaging(packaging_dir: Path, built_since: float):
    deb: Dict[str, List[Path]] = {}
    rpm: Dict[str, List[Path]] = {}
    sboms: List[Path] = []
    if not packaging_dir.exists():
        return deb, rpm, sboms
    for p in packaging_dir.iterdir():
        if not p.is_file():
            continue
        try:
            if p.stat().st_mtime <= built_since:
                continue
        except FileNotFoundError:
            continue
        kind, distro = parse_artifact(p)
        if kind == "deb":
            deb.setdefault(distro or "unknown", []).append(p)
        elif kind == "rpm":
            rpm.setdefault(distro or "unknown", []).append(p)
        elif kind == "sbom":
            sboms.append(p)
    return deb, rpm, sboms


# --- Repo metadata ---
def apt_flat_repo(deb_dir: Path, channel: str):
    deb_dir = Path(deb_dir).resolve()

    debs = list(deb_dir.glob("*.deb"))
    if not debs:
        return

    def log(msg: str):
        print(msg, flush=True)

    # Resolve the directory of THIS script (not the current working dir)
    try:
        SCRIPT_DIR = Path(__file__).resolve().parent
    except NameError:
        # __file__ may not exist in interactive contexts; fall back to CWD
        SCRIPT_DIR = Path.cwd()

    # GPG env controls (unchanged)
    GPG_KEYID = os.environ.get("GPG_KEYID", "").strip()
    GPG_HOMEDIR = os.environ.get("GPG_HOMEDIR", "").strip()
    GPG_EXTRA = os.environ.get("GPG_EXTRA", "").strip()
    APTFTPARCHIVE_ENV = os.environ.get("APTFTPARCHIVE", "").strip()
    DPKG_SCANPACKAGES_ENV = os.environ.get("DPKG_SCANPACKAGES", "").strip()

    # Tool resolution
    scan_candidates: List[str] = []
    if DPKG_SCANPACKAGES_ENV:
        scan_candidates.append(DPKG_SCANPACKAGES_ENV)
    local_scan = SCRIPT_DIR / "bin" / "dpkg-scanpackages"
    if local_scan.is_file() and os.access(local_scan, os.X_OK):
        scan_candidates.append(str(local_scan))
    path = shutil.which("dpkg-scanpackages")
    if path:
        scan_candidates.append(path)
    scan = next((c for c in scan_candidates if c), None)

    # Prefer ./bin/apt-ftparchive (next to the build script),
    # then PATH, then env
    aptft_candidates: List[str] = []
    local_aptft = SCRIPT_DIR / "bin" / "apt-ftparchive"
    if local_aptft.is_file() and os.access(local_aptft, os.X_OK):
        aptft_candidates.append(str(local_aptft))
    path = shutil.which("apt-ftparchive")
    if path:
        aptft_candidates.append(path)
    if APTFTPARCHIVE_ENV:
        aptft_candidates.append(APTFTPARCHIVE_ENV)

    # First non-empty candidate wins
    aptft = next((c for c in aptft_candidates if c), None)

    if not scan and not aptft:
        log("INFO: dpkg-scanpackages/apt-ftparchive not found; "
            f"skipping APT metadata in {deb_dir}.")
        return

    log(f"Generating APT metadata in {deb_dir} ...")

    packages = deb_dir / "Packages"
    packages_gz = deb_dir / "Packages.gz"
    release = deb_dir / "Release"
    inrelease = deb_dir / "InRelease"
    release_gpg = deb_dir / "Release.gpg"

    # Clean old indices/signatures
    for p in (packages, packages_gz, inrelease, release_gpg):
        try:
            p.unlink()
        except Exception:
            pass

    # Create Packages
    try:
        if scan:
            with open(packages, "wb") as outf:
                subprocess.run([scan, ".", "/dev/null"], cwd=deb_dir,
                               check=True, stdout=outf)
        else:
            with open(packages, "wb") as outf:
                if aptft is None:
                    raise RuntimeError("apt-ftparchive not found")
                subprocess.run([aptft, "packages", "."], cwd=deb_dir,
                               check=True, stdout=outf)
    except subprocess.CalledProcessError as e:
        # Non-zero exit may be a warning; check if Packages file was created
        if packages.exists() and packages.stat().st_size > 0:
            log(f"WARN: {scan or aptft} returned non-zero exit code "
                f"{e.returncode}, but Packages file was created "
                f"({packages.stat().st_size} bytes). Continuing.")
        else:
            log(f"ERROR: {scan or aptft} failed with exit code {e.returncode} "
                f"and Packages file is missing or empty. Skipping APT metadata "
                f"for {deb_dir}.")
            return

    # gzip -n -c Packages > Packages.gz
    try:
        with open(packages_gz, "wb") as gzout, open(packages, "rb") as pin:
            subprocess.run(["gzip", "-n", "-c"], cwd=deb_dir, check=True,
                           stdin=pin, stdout=gzout)
    except subprocess.CalledProcessError as e:
        log(f"WARN: gzip failed with exit code {e.returncode}. "
            f"Packages.gz will not be available for {deb_dir}.")
        # Continue without .gz - the uncompressed Packages file is sufficient

    # Build Release atomically
    try:
        release.unlink()
    except Exception:
        pass

    archs = set()
    for deb in debs:
        if "_amd64.deb" in deb.name:
            archs.add("amd64")
        elif "_arm64.deb" in deb.name:
            archs.add("arm64")
    if not archs:
        log("WARN: could not detect architecture from DEB filenames in "
            f"{deb_dir}; defaulting to amd64")
        archs.add("amd64")
    archs_str = " ".join(sorted(archs))
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(deb_dir))
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            header = (
                "Origin: Himmelblau\n"
                "Label: Himmelblau\n"
                f"Suite: {channel}\n"
                f"Codename: {deb_dir.name}\n"
                f"Architectures: {archs_str}\n"
                "Components: main\n"
            ).encode("utf-8")
            tmp.write(header)

            if aptft:
                try:
                    proc = subprocess.run([aptft, "release", "."], cwd=deb_dir,
                                          check=True, stdout=subprocess.PIPE)
                    tmp.write(proc.stdout)
                except subprocess.CalledProcessError as e:
                    log(f"WARN: apt-ftparchive release failed with exit code "
                        f"{e.returncode}. Release file will have minimal metadata.")
                    # Continue with header-only Release file

        os.replace(tmp_path, release)
    finally:
        if Path(tmp_path).exists() and not release.exists():
            try:
                Path(tmp_path).unlink()
            except Exception:
                pass

    # Re-sign
    for p in (inrelease, release_gpg):
        try:
            p.unlink()
        except Exception:
            pass

    if release.exists():
        sign_common = ["gpg", "--batch", "--yes",
                       "--pinentry-mode", "loopback"]
        if GPG_HOMEDIR:
            sign_common += ["--homedir", GPG_HOMEDIR]
        if GPG_EXTRA:
            sign_common += GPG_EXTRA.split()

        if GPG_KEYID:
            sign_inrelease = sign_common + ["--local-user", GPG_KEYID,
                                            "--clearsign", "-o", "InRelease",
                                            "Release"]
            sign_release_gpg = sign_common + ["--local-user", GPG_KEYID,
                                              "-abs", "-o", "Release.gpg",
                                              "Release"]
        else:
            sign_inrelease = sign_common + ["--clearsign", "-o", "InRelease",
                                            "Release"]
            sign_release_gpg = sign_common + ["-abs", "-o", "Release.gpg",
                                              "Release"]

        log(f"Signing APT Release in {deb_dir} ...")
        try:
            subprocess.run(sign_inrelease, cwd=deb_dir, check=True)
            subprocess.run(sign_release_gpg, cwd=deb_dir, check=True)
        except subprocess.CalledProcessError as e:
            log(f"WARN: GPG signing failed with exit code {e.returncode}. "
                f"Repository metadata will be unsigned.")
            # Continue with unsigned repository
    else:
        log(f"{release} is missing!")

    log("Done: " + " ".join(
        str(p) for p in [packages, packages_gz, release,
                         inrelease, release_gpg] if Path(p).exists()
    ))


def sign_rpm_repo(rpm_dir: Path):
    gpg = which("gpg")
    if gpg is None:
        log(f"INFO: gpg not found; skipping signing RPM repo {rpm_dir}.")
        return
    repodata = rpm_dir / "repodata"
    log(f"Signing RPM repo in {repodata} ...")
    subprocess.run([gpg, "--detach-sign", "--armor", "repomd.xml"],
                   cwd=repodata, check=True)


def create_repo_file(rpm_dir: Path):
    """
    Create 'himmelblau.repo' inside rpm_dir, deriving:
      - channel: 'stable' or 'nightly'
      - version: e.g. 'latest' or a timestamped/versioned dir
      - distro:  last path component (e.g., 'fedora42', 'fedora43', 'rawhide',
                                        'tumbleweed')

    Expected layout (examples):
      /.../stable/<version>/rpm/<distro>
      /.../nightly/<version>/rpm/<distro>

    The generated baseurl:
      https://packages.himmelblau-idm.org/{channel}/{version}/rpm/{distro}/
    """
    parts = list(rpm_dir.parts)

    # Find channel in the path
    if "stable" in parts:
        ch_idx = parts.index("stable")
        channel = "stable"
    elif "nightly" in parts:
        ch_idx = parts.index("nightly")
        channel = "nightly"
    else:
        raise ValueError("Path does not contain 'stable' or 'nightly': "
                         f"{rpm_dir}")

    # Version is the segment immediately after the channel
    if len(parts) <= ch_idx + 1:
        raise ValueError(f"Path missing version component after '{channel}': "
                         f"{rpm_dir}")
    version = parts[ch_idx + 1]  # e.g. 'latest' or '2025-11-10-13c22d1890ad'

    # Basic sanity check for '/rpm/<distro>'
    # We accept any distro name; just ensure 'rpm' is present
    #                               before the last segment
    try:
        rpm_idx = parts.index("rpm", ch_idx + 2)
    except ValueError:
        raise ValueError("Path does not contain '/rpm/' after version: "
                         f"{rpm_dir}")
    if rpm_idx != len(parts) - 2:
        # Expect .../<channel>/<version>/rpm/<distro>
        # (rpm should be the penultimate element)
        # don't hard-fail; just proceed
        # (allows extra nesting if you really have it)
        pass

    distro = rpm_dir.name  # last component
    base_url = (
        f"https://packages.himmelblau-idm.org/{channel}/"
        f"{version}/rpm/{distro}/"
    )
    gpgkey_url = "https://packages.himmelblau-idm.org/himmelblau.asc"

    repo_content = (
        "[himmelblau]\n"
        f"name=Himmelblau ({distro}, {channel} {version})\n"
        f"baseurl={base_url}\n"
        "enabled=1\n"
        "gpgcheck=1\n"
        "repo_gpgcheck=1\n"
        f"gpgkey={gpgkey_url}\n"
    )

    repo_path = rpm_dir / "himmelblau.repo"
    repo_path.write_text(repo_content, encoding="utf-8")
    return repo_path


def rpm_repo(rpm_dir: Path):
    rpms = list(rpm_dir.glob("*.rpm"))
    if not rpms:
        return
    cr = which("createrepo_c") or which("createrepo")
    if not cr:
        log("INFO: createrepo_c/createrepo not found; "
            f"skipping RPM metadata in {rpm_dir}.")
        return
    log(f"Generating RPM repodata in {rpm_dir} ...")
    subprocess.run([cr, "."], cwd=rpm_dir, check=True)
    sign_rpm_repo(rpm_dir)
    create_repo_file(rpm_dir)


# --- Publish ---
def publish_per_distro(publish_root: Path, channel: str, label: str,
                       deb_map: Dict[str, List[Path]],
                       rpm_map: Dict[str, List[Path]],
                       sboms: List[Path]):
    base = publish_root / channel / label
    ensure_dir(base)

    for distro, files in sorted(deb_map.items()):
        dst = base / "deb" / distro
        ensure_dir(dst)
        for f in files:
            shutil.copy2(f, dst / f.name)
        apt_flat_repo(dst, channel)

    for distro, files in sorted(rpm_map.items()):
        dst = base / "rpm" / distro
        ensure_dir(dst)
        for f in files:
            shutil.copy2(f, dst / f.name)
        rpm_repo(dst)

    if sboms:
        sbdir = base / "sbom"
        ensure_dir(sbdir)
        for f in sboms:
            shutil.copy2(f, sbdir / f.name)

    # Make sure the generated repo isn't empty (due to build failure).
    # If the build failed, we don't want to flag it as latest.
    rpm_dir = base / "rpm"
    deb_dir = base / "deb"
    if rpm_dir.exists() or deb_dir.exists():
        latest = publish_root / channel / "latest"
        try:
            if latest.exists() or latest.is_symlink():
                latest.unlink()
        except FileNotFoundError:
            pass
        os.symlink(label, latest)


# --- Missing-distro retry helpers ---
DISTRO_LINE_RE = re.compile(r'^\s*-\s*make\s+([a-z0-9.]+)\s*$',
                            re.IGNORECASE | re.MULTILINE)
ARM64_SUPPORTED_RE = re.compile(r'\barm64-([a-z0-9.]+)\b')


def parse_per_distro_targets_via_make_help(
        repo: Path
) -> Tuple[List[str], List[str]]:
    """
    Checkout origin/main, run `make help`, parse both the 'Per-distro' target
    lines and the ARM64 'Supported:' targets, then restore the previous HEAD.
    Returns (per_distro_targets, arm64_targets). Returns ([], []) on failure.
    """
    # Remember where we started
    try:
        current_head = git_rev_parse(repo, "HEAD")
    except Exception:
        current_head = None

    targets: List[str] = []
    arm64_targets: List[str] = []
    try:
        # ensure we use the Makefile as it exists on main
        checkout_clean(repo, "origin/main")
        # run make help and capture output
        res = run(["/usr/bin/make", "help"], cwd=repo, capture=True)
        txt = res.stdout.decode(errors="replace")
        candidates = DISTRO_LINE_RE.findall(txt)

        # de-dupe while preserving order
        seen = set()
        for t in candidates:
            if t not in seen:
                targets.append(t)
                seen.add(t)

        if targets:
            log(f"Parsed {len(targets)} per-distro targets from "
                "`make help` on origin/main.")
        else:
            log("WARN: no per-distro targets found in `make help` output.")

        # Parse ARM64 targets from the 'Supported: arm64-...' line
        arm64_seen = set()
        for line in txt.splitlines():
            if "Supported:" in line:
                for distro in ARM64_SUPPORTED_RE.findall(line):
                    tgt = f"arm64-{distro}"
                    if tgt not in arm64_seen:
                        arm64_targets.append(tgt)
                        arm64_seen.add(tgt)

        if arm64_targets:
            log(f"Parsed {len(arm64_targets)} arm64 targets "
                "from `make help` on origin/main.")
        else:
            log("WARN: no arm64 targets found in `make help` output.")
    except subprocess.CalledProcessError as e:
        log(f"WARN: `make help` failed (rc={e.returncode}); "
            "cannot determine per-distro targets.")
    except Exception as e:
        log(f"WARN: error running `make help`: {e}")
    finally:
        # restore original checkout if we had it
        if current_head:
            try:
                checkout_clean(repo, current_head)
            except Exception as e:
                log("WARN: failed to restore previous HEAD after make help: "
                    f"{e}")

    # Skip building on gentoo
    return ([t for t in targets if t != "gentoo"],
            [t for t in arm64_targets if t != "gentoo"])


def target_is_deb(t: str) -> bool:
    distro = t[len("arm64-"):] if t.startswith("arm64-") else t
    return distro.startswith("ubuntu") or distro.startswith("debian")


def published_has_pkgs(base: Path, t: str) -> bool:
    """
    Returns True if the publish dir already contains at least
    one artifact for target t.
    Targets prefixed with 'arm64-' are checked for arm64-specific artifacts;
    all other targets are checked for amd64-specific artifacts.
    """
    is_arm64 = t.startswith("arm64-")
    distro = t[len("arm64-"):] if is_arm64 else t
    if target_is_deb(t):
        if is_arm64:
            d = base / "deb" / f"{distro}-arm64"
            pattern = "*_arm64.deb"
        else:
            d = base / "deb" / distro
            pattern = "*_amd64.deb"
        return d.is_dir() and any(d.glob(pattern))
    else:
        # aarch64 packages live in a separate "<distro>-aarch64" directory.
        # All other arches (x86_64, noarch) use the plain "<distro>"
        # directory.
        if is_arm64:
            d = base / "rpm" / f"{distro}-aarch64"
        else:
            d = base / "rpm" / distro
        if not d.is_dir():
            return False

        # Support both known RPM naming styles:
        #   <name>.<arch>.rpm
        #   <name>.<arch>-<distro>.rpm
        patterns = ("*.aarch64.rpm", "*aarch64-*.rpm") if is_arm64 else ("*.x86_64.rpm", "*x86_64-*.rpm")
        for pattern in patterns:
            if any(d.glob(pattern)):
                return True
        return False


def compute_missing_targets_in_label(
        publish_root: Path, channel: str,
        label: str, expected_targets: List[str]) -> List[str]:
    base = publish_root / channel / label
    if not base.exists():
        return []
    missing: List[str] = []
    for t in expected_targets:
        if not published_has_pkgs(base, t):
            missing.append(t)
    if missing:
        log(f"{channel}/{label}: missing {len(missing)} targets -> "
            f"{', '.join(missing)}")
    else:
        log(f"{channel}/{label}: no missing targets.")
    return missing


def publish_incremental(publish_root: Path, channel: str, label: str,
                        deb_map: Dict[str, List[Path]],
                        rpm_map: Dict[str, List[Path]], sboms: List[Path]):
    """
    Append artifacts to an existing label directory
    and regenerate metadata only for touched distros.
    """
    base = publish_root / channel / label
    ensure_dir(base)

    for distro, files in sorted(deb_map.items()):
        dst = base / "deb" / distro
        ensure_dir(dst)
        for f in files:
            shutil.copy2(f, dst / f.name)
        apt_flat_repo(dst, channel)

    for distro, files in sorted(rpm_map.items()):
        dst = base / "rpm" / distro
        ensure_dir(dst)
        for f in files:
            shutil.copy2(f, dst / f.name)
        rpm_repo(dst)

    if sboms:
        sbdir = base / "sbom"
        ensure_dir(sbdir)
        for f in sboms:
            shutil.copy2(f, sbdir / f.name)


def patch_signing_keys(filename):
    old_hexes = [
        "0xFFE471BA97CD96ED7330E0B4F5A25D2D6AA97EC9",
        "0x3D46C88168B2FF8D75D0B1786CCA48F23916FC03",
    ]
    new_hex = "0xE87FD8D463A5E4814B9CDBA90CC0D4002C425E03"

    # Read file contents
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()

    # Replace all occurrences
    for old in old_hexes:
        content = content.replace(old, new_hex)

    # Write back to file (in-place)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)


def make_sign_rpms(repo: Path, env: Optional[dict]) -> int:
    log("Running: make sign-rpms")
    try:
        run(["/usr/bin/make", "sign-rpms"], cwd=repo, env=env)
        return 0
    except subprocess.CalledProcessError as e:
        return e.returncode


def retry_missing_for_stable(
        repo: Path, publish_root: Path, expected_targets: List[str]):
    # Discover the latest stable tag that already
    # has a publish dir (or symlink).
    tags = sorted([t for t in git_list_tags(repo) if STABLE_TAG_RE.match(t)],
                  key=version.parse, reverse=True)
    for t in [t for t in tags if "beta" not in t and "alpha" not in t]:
        label_dir = publish_root / "stable" / t
        if label_dir.exists():
            latest_tag = t
            break
    else:
        return  # Nothing published yet

    # Find which stable branch contains this tag
    stable_branch = None
    for branch in SUPPORTED_BRANCHES:
        if tag_on_branch(repo, latest_tag, branch):
            stable_branch = branch
            break

    if not stable_branch:
        log(f"WARN: tag {latest_tag} not found on any supported branch; "
            "skipping retry")
        return

    missing = compute_missing_targets_in_label(publish_root, "stable",
                                               latest_tag, expected_targets)
    if not missing:
        return
    # Build missing targets using the branch tip (not the tag itself).
    # This allows build fixes pushed to the branch to be picked up without
    # requiring a new release tag.
    log(f"Building from branch tip origin/{stable_branch} "
        f"(publishing as {latest_tag})")
    checkout_clean(repo, f"origin/{stable_branch}")
    patch_signing_keys(repo / "Makefile")
    env = os.environ.copy()
    started = time.time()
    for tgt in missing:
        make_target(repo, tgt, env)
    make_sign_rpms(repo, env)
    deb_map, rpm_map, sboms = collect_from_packaging(repo / PACKAGING_DIR,
                                                     built_since=started)
    publish_incremental(publish_root, "stable", latest_tag, deb_map,
                        rpm_map, sboms)


def resolve_nightly_latest_label(publish_root: Path) -> Optional[str]:
    latest = publish_root / "nightly" / "latest"
    if latest.is_symlink():
        try:
            return os.readlink(latest)
        except OSError:
            return None
    # Fallback: pick most recent directory
    # (lexicographically should be fine with YYYY-MM-DD-commit form)
    nightly_root = publish_root / "nightly"
    if nightly_root.exists():
        labels = [p.name for p in nightly_root.iterdir() if p.is_dir()]
        if labels:
            return sorted(labels, reverse=True)[0]
    return None


def nightly_label_commit_prefix(label: str) -> Optional[str]:
    if not label:
        return None
    if "-" not in label:
        return None
    _, commit_prefix = label.rsplit("-", 1)
    if not commit_prefix or commit_prefix == "unknown":
        return None
    return commit_prefix


def retry_missing_for_nightly(
        repo: Path, publish_root: Path, expected_targets: List[str]):
    label = resolve_nightly_latest_label(publish_root)
    if not label:
        return
    tip = git_rev_parse(repo, "origin/main")
    label_prefix = nightly_label_commit_prefix(label)
    if label_prefix and tip and not tip.startswith(label_prefix):
        log(f"Nightly retry skipped: latest label {label} is behind "
            f"origin/main ({tip[:12]}).")
        return
    missing = compute_missing_targets_in_label(publish_root, "nightly", label,
                                               expected_targets)
    if not missing:
        return
    # Build missing targets from origin/main
    checkout_clean(repo, "origin/main")
    env = os.environ.copy()
    # Derive the date suffix from the existing label (YYYY-MM-DD-<commit>)
    # so retries produce the same version as the original nightly build.
    m = NIGHTLY_LABEL_RE.match(label)
    label_date = m.group("date").replace("-", "") if m else dt.datetime.utcnow().strftime("%Y%m%d")
    env["DEB_REVISION_APPEND"] = f"~{label_date}"
    started = time.time()
    for tgt in missing:
        make_target(repo, tgt, env)
    deb_map, rpm_map, sboms = collect_from_packaging(repo / PACKAGING_DIR,
                                                     built_since=started)
    publish_incremental(publish_root, "nightly", label, deb_map,
                        rpm_map, sboms)


# --- Planning + bootstrap helpers ---
def find_latest_stable_tag(repo: Path, branch: str) -> Optional[str]:
    candidates = [t for t in git_list_tags(repo)
                  if STABLE_TAG_RE.match(t) and tag_on_branch(repo, t, branch)]
    if not candidates:
        return None
    candidates.sort(key=version.parse, reverse=True)
    return candidates[0]


def plan_stable(repo: Path, branch: str, state: Dict) -> List[str]:
    built = set(state.get("built_tags", {}).get(branch, []))
    to_build: List[str] = []
    for t in sorted(git_list_tags(repo)):
        if not STABLE_TAG_RE.match(t):
            continue
        if t in built:
            continue
        if tag_on_branch(repo, t, branch):
            to_build.append(t)
    if to_build:
        log(f"Stable planner: {branch} -> new tags: {', '.join(to_build)}")
    else:
        log(f"Stable planner: {branch} -> no new tags.")
    return to_build


def plan_nightly(
        repo: Path, state: Dict, force_daily: bool
) -> Tuple[bool, str, str]:
    tip = git_rev_parse(repo, "origin/main")
    last_commit = state.get("nightly", {}).get("last_commit")
    today = utc_today()
    last_date = state.get("nightly", {}).get("last_date")
    if tip != last_commit:
        log(f"Nightly planner: main changed ({tip[:12]}), will build.")
        return True, tip, today
    if force_daily and last_date != today:
        log("Nightly planner: forcing daily build.")
        return True, tip, today
    log("Nightly planner: up-to-date; skip.")
    return False, tip, today


def needs_bootstrap_stable(publish_root: Path, tag: Optional[str]) -> bool:
    if not tag:
        return False
    tag_dir = publish_root / "stable" / tag
    latest = publish_root / "stable" / "latest"
    return not tag_dir.exists() or not latest.exists()


def needs_bootstrap_nightly(publish_root: Path, label: str) -> bool:
    label_dir = publish_root / "nightly" / label
    latest = publish_root / "nightly" / "latest"
    return not label_dir.exists() or not latest.exists()


# --- Main ---
def main():
    ap = argparse.ArgumentParser(
        description="Himmelblau autobuilder/publisher (per-distro) "
                    "with bootstrap + missing-distro retries")
    ap.add_argument("--repo-dir", type=Path, default=DEFAULT_REPO_DIR)
    ap.add_argument("--publish-dir", type=Path, default=DEFAULT_PUBLISH_DIR)
    ap.add_argument("--force-daily", action="store_true")
    ap.add_argument("--log-file", type=Path)
    args = ap.parse_args()

    # Initialize logging (nightly log is the default/base log file)
    if args.log_file:
        switch_log(args.log_file)

    publish_root = args.publish_dir
    ensure_dir(publish_root)
    state_path = publish_root / STATE_FILE
    state = load_state(state_path)

    lock = FileLock(publish_root / LOCK_FILE)
    try:
        lock.acquire()
    except Exception:
        log("Another run in progress; exiting.")
        return 0

    try:
        repo = args.repo_dir
        if not repo.exists():
            log(f"ERROR: repo-dir does not exist: {repo}")
            return 2

        packaging_dir = repo / PACKAGING_DIR
        git_fetch_all(repo)

        # Always parse expected per-distro targets from origin/main
        expected_targets, arm64_targets = (
            parse_per_distro_targets_via_make_help(repo)
        )

        # ===== Retry missing BEFORE planning new builds =====
        if expected_targets:
            # Stable retry (switch to branch-specific log)
            for branch in SUPPORTED_BRANCHES:
                if args.log_file:
                    switch_log(Path(str(args.log_file) + f".{branch}"))
                try:
                    retry_missing_for_stable(repo, publish_root,
                                             expected_targets)
                except Exception as e:
                    log(f"WARN: stable retry encountered an error: {e}")

            # Nightly retry (switch back to base log)
            if args.log_file:
                switch_log(args.log_file)
            try:
                retry_missing_for_nightly(repo, publish_root, expected_targets)
            except Exception as e:
                log(f"WARN: nightly retry encountered an error: {e}")

        if arm64_targets:
            # ARM64 stable retry
            # (single run; function determines applicable stable branch)
            if args.log_file:
                switch_log(Path(str(args.log_file) +
                                f".{SUPPORTED_BRANCHES[0]}"))
            try:
                retry_missing_for_stable(repo, publish_root, arm64_targets)
            except Exception as e:
                log(f"WARN: arm64 stable retry encountered an error: {e}")

            # ARM64 nightly retry
            if args.log_file:
                switch_log(args.log_file)
            try:
                retry_missing_for_nightly(repo, publish_root, arm64_targets)
            except Exception as e:
                log(f"WARN: arm64 nightly retry encountered an error: {e}")

        # ===== Normal stable flow (new tags) =====
        for branch in SUPPORTED_BRANCHES:
            # Switch to branch-specific log for stable builds
            if args.log_file:
                switch_log(Path(str(args.log_file) + f".{branch}"))
            latest_stable = find_latest_stable_tag(repo, branch)
            if needs_bootstrap_stable(publish_root, latest_stable):
                if latest_stable:
                    log(f"Bootstrap: publishing latest stable tag "
                        f"{latest_stable} ...")
                    checkout_clean(repo, latest_stable)
                    patch_signing_keys(repo / "Makefile")
                    env = os.environ.copy()
                    started = time.time()
                    rc = make_package(repo, env)
                    if rc != 0:
                        log(f"ERROR: Some builds failed for {latest_stable} "
                            f"(rc={rc})")
                    rc_arm64 = make_arm64(repo, env)
                    if rc_arm64 != 0:
                        log(f"ERROR: Some arm64 builds failed for "
                            f"{latest_stable} (rc={rc_arm64})")
                    deb_map, rpm_map, sboms = collect_from_packaging(
                        packaging_dir, built_since=started)
                    has_artifacts = bool(deb_map or rpm_map or sboms)
                    if not has_artifacts:
                        log(f"WARN: no stable artifacts found for "
                            f"{latest_stable}; skipping publish/state update.")
                    else:
                        publish_per_distro(publish_root, "stable",
                                           latest_stable, deb_map,
                                           rpm_map, sboms)
                        if rc == 0:
                            state.setdefault("built_tags", {}).setdefault(
                                                                branch, [])
                            built = state["built_tags"][branch]
                            if latest_stable not in built:
                                state["built_tags"][branch].append(
                                                        latest_stable)
                            save_state(state_path, state)
                        else:
                            log("WARN: stable build failed for "
                                f"{latest_stable}; not marking tag as built.")

        # ===== Normal nightly planner =====
        # Switch back to base log for nightly builds
        if args.log_file:
            switch_log(args.log_file)
        should, tip2, today = plan_nightly(repo, state, args.force_daily)
        if should:
            checkout_clean(repo, "origin/main")
            env = os.environ.copy()
            env["DEB_REVISION_APPEND"] = f"~{today.replace('-', '')}"
            started = time.time()
            rc = make_package(repo, env)
            if rc != 0:
                log(f"ERROR: Some nightly builds failed (rc={rc})")
            rc_arm64 = make_arm64(repo, env)
            if rc_arm64 != 0:
                log(f"ERROR: Some nightly arm64 builds failed (rc={rc_arm64})")
            deb_map, rpm_map, sboms = (
                collect_from_packaging(packaging_dir, built_since=started)
            )
            label = f"{today}-{(tip2 or 'unknown')[:12]}"
            has_artifacts = bool(deb_map or rpm_map or sboms)
            if not has_artifacts:
                log("WARN: no nightly artifacts found; "
                    "skipping publish/state update.")
            else:
                publish_per_distro(publish_root, "nightly", label,
                                   deb_map, rpm_map, sboms)
                if rc == 0:
                    state.setdefault("nightly", {})["last_commit"] = tip2
                    state["nightly"]["last_date"] = today
                    save_state(state_path, state)
                else:
                    log("WARN: nightly build failed; "
                        "not marking commit as built.")

        log("Done.")
        return 0
    finally:
        lock.release()
        subprocess.run(
            ["find", publish_root, "-type", "f", "-name",
             "Release", "-exec", "chmod", "0644", "{}", "+"],
            check=True
        )


if __name__ == "__main__":
    sys.exit(main())
