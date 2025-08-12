"""Nuclei template collector with rich progress and logging."""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
import shutil
import signal
import subprocess
import time
import errno
import random
import datetime
import tempfile
from hashlib import sha1
from urllib.parse import urlparse

import requests
from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    ProgressColumn,
)
from rich.spinner import Spinner
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm, Prompt


console = Console()
CANCEL_REQUESTED = False


class AnimatedSpinnerColumn(ProgressColumn):
    """Progress column that shows a configurable spinner per task."""

    def render(self, task):
        name = task.fields.get("spinner", "dots")
        return Spinner(name)


STATE_SPINNERS = {
    "head": "dots",  # 🔍
    "clone": "line",  # ⬇️
    "retry": "earth",  # ♻️
    "zip": "toggle",  # 📦
    "extract": "bouncingBar",  # 📂
    "copy": "runner",  # 📄
    "done": "moon",  # ✅
    "cleanup": "dots",  # 🧹
    "wait": "clock",  # 💤
}


# status icons for high level repository state
STATUS_ICONS = {
    "existing": "📦",
    "up_to_date": "✅",
    "updating": "🛠️",
    "skipped": "⏭️",
    "failed": "❌",
}


def normalize_repo_url(url: str) -> str:
    """Normalize repository URL to avoid duplicates."""
    url = url.strip()
    if url.endswith(".git"):
        url = url[:-4]
    return url.rstrip("/")


def repo_cache_path(url: str, cache_root: str) -> str:
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        org, repo = parts[:2]
    else:
        org, repo = "unknown", parts[0]
    folder = f"{org}__{repo}"
    return os.path.join(cache_root, folder)


def compute_sha1(path: str) -> str:
    h = sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_segment(segment: str) -> str:
    """Return a filesystem-safe segment."""
    allowed = "-_." + ''.join(chr(i) for i in range(ord('a'), ord('z')+1)) + ''.join(chr(i) for i in range(ord('0'), ord('9')+1))
    segment = segment.lower()
    return ''.join(c if c in allowed else '-' for c in segment)[:40]


def store_path(store_dir: str, hash_val: str) -> str:
    """Return path in content store for given hash."""
    sub = os.path.join(store_dir, hash_val[:2])
    os.makedirs(sub, exist_ok=True)
    return os.path.join(sub, f"{hash_val}.yaml")


def hardlink_or_copy(src: str, dst: str) -> None:
    """Create a hard link if possible else copy."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def parse_size(value: str) -> int | None:
    """Parse human-readable size like ``1G`` into bytes."""
    if not value:
        return None
    value = value.strip()
    units = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    try:
        if value[-1].lower() in units:
            return int(float(value[:-1]) * units[value[-1].lower()])
        return int(value)
    except ValueError:
        return None


def discover_mounts(threshold: int = 512 * 1024 * 1024) -> list[tuple[int, str, int]]:
    """Return list of candidate mounts as ``(free_bytes, mount, use_percent)``."""

    try:
        out = subprocess.check_output(["df", "-PkT"], text=True).splitlines()
    except Exception:
        return []

    candidates: list[tuple[int, str, int]] = []
    for line in out[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        fstype = parts[1]
        avail = int(parts[4]) * 1024
        usep = parts[5]
        mount = parts[6]
        if fstype in {
            "proc",
            "sysfs",
            "cgroup",
            "cgroup2",
            "overlay",
            "squashfs",
            "tmpfs",
            "devtmpfs",
            "nsfs",
        }:
            continue
        try:
            use_val = int(usep.rstrip("%"))
        except ValueError:
            use_val = 0
        if use_val >= 99:
            continue
        if avail < threshold:
            continue
        if not os.path.isdir(mount) or not os.access(mount, os.W_OK):
            continue
        candidates.append((avail, mount, use_val))
    candidates.sort(reverse=True)
    return candidates


def validate_mount(path: str) -> tuple[bool, str]:
    """Check that ``path`` resides on a writable filesystem with space and inodes."""

    probe_dir = os.path.join(path, "afo", "probe")
    probe_file = os.path.join(probe_dir, "._afo_probe.tmp")
    data = os.urandom(1024 * 1024)
    try:
        os.makedirs(probe_dir, exist_ok=True)
        st = os.statvfs(probe_dir)
        if st.f_favail == 0:
            return False, "no inodes"
        with open(probe_file, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        with open(probe_file, "rb") as f:
            start = f.read(4096)
            f.seek(-4096, os.SEEK_END)
            end = f.read(4096)
        if start != data[:4096] or end != data[-4096:]:
            return False, "mismatch"
        return True, ""
    except OSError as e:
        if e.errno == errno.EROFS:
            reason = "read-only"
        elif e.errno == errno.ENOSPC:
            reason = "no space"
        elif e.errno == errno.EDQUOT:
            reason = "quota"
        elif e.errno == errno.EACCES:
            reason = "permission"
        else:
            reason = e.strerror or "error"
        return False, reason
    finally:
        try:
            if os.path.exists(probe_file):
                os.remove(probe_file)
            shutil.rmtree(os.path.join(path, "afo", "probe"), ignore_errors=True)
        except Exception:
            pass


def mount_point(path: str) -> str:
    """Return mount point for ``path``."""

    try:
        out = subprocess.check_output(["df", "-P", path], text=True).splitlines()
        if len(out) >= 2:
            return out[1].split()[-1]
    except Exception:
        pass
    return "?"


class DiskSpaceError(Exception):
    """Raised when disk space falls below the safety threshold."""

    def __init__(self, path: str):
        super().__init__(path)
        self.path = path


def check_free_space(paths: list[str], threshold: int = 150 * 1024 * 1024) -> tuple[bool, str | None]:
    """Ensure all ``paths`` have at least ``threshold`` bytes free.

    Returns ``(True, None)`` if enough space, else ``(False, offending_path)``.
    """

    for p in paths:
        try:
            if shutil.disk_usage(p).free < threshold:
                return False, p
        except OSError:
            return False, p
    return True, None



def ensure_symlink(link: str, target: str, logger: logging.Logger) -> None:
    """Ensure ``link`` points to ``target`` using a symlink.

    If ``link`` exists as a directory, move its contents to ``target`` first.
    Falls back to plain directories if symlinks are unsupported.
    """

    target = os.path.abspath(target)
    if os.path.islink(link):
        current = os.path.realpath(link)
        if current == target:
            return
        os.unlink(link)
    elif os.path.isdir(link):
        if os.path.abspath(link) != target:
            os.makedirs(target, exist_ok=True)
            for name in os.listdir(link):
                shutil.move(os.path.join(link, name), target)
            os.rmdir(link)
            logger.info("Moved %s contents to %s", link, target)
        else:
            return
    elif os.path.exists(link):
        os.remove(link)

    os.makedirs(target, exist_ok=True)
    try:
        os.symlink(target, link)
        logger.info("Symlinked %s -> %s", link, target)
    except OSError:
        logger.warning("Symlinks unsupported for %s; using regular directory", link)
        os.makedirs(link, exist_ok=True)


def run_setup(args) -> tuple[str, dict]:
    """Run interactive setup wizard or load existing configuration."""

    default_output = os.environ.get("AFO_OUTPUT_DIR") or args.output_dir
    default_output = os.path.abspath(os.path.expanduser(default_output))

    interactive = sys.stdin.isatty() and sys.stdout.isatty() and not args.yes

    if interactive and not os.environ.get("AFO_OUTPUT_DIR"):
        try:
            output_dir = Prompt.ask(
                "Output directory? (default: ./Templates)", default=default_output
            )
        except KeyboardInterrupt:
            console.print("[red]Setup cancelled[/]")
            raise SystemExit(1)
    else:
        output_dir = default_output

    output_dir = os.path.abspath(os.path.expanduser(output_dir))
    os.makedirs(output_dir, exist_ok=True)
    ok, reason = validate_mount(output_dir)
    while not ok:
        if not interactive:
            console.print(f"[red]{output_dir}: {reason}[/]")
            raise SystemExit(1)
        console.print(f"[red]{output_dir}: {reason}[/]")
        try:
            output_dir = Prompt.ask("Output directory?", default=default_output)
        except KeyboardInterrupt:
            console.print("[red]Setup cancelled[/]")
            raise SystemExit(1)
        output_dir = os.path.abspath(os.path.expanduser(output_dir))
        os.makedirs(output_dir, exist_ok=True)
        ok, reason = validate_mount(output_dir)

    config_path = os.path.join(output_dir, "afo.config.json")
    if not args.setup and not args.reset_config and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        return output_dir, config

    candidates = discover_mounts()
    candidate_info: list[tuple[int, str, bool, str]] = []
    validated: list[tuple[int, str]] = []
    skipped_msgs: list[str] = []
    for avail, mount, _ in candidates:
        ok, reason = validate_mount(mount)
        candidate_info.append((avail, mount, ok, reason))
        if ok:
            validated.append((avail, mount))
        else:
            skipped_msgs.append(f"{mount} ({reason})")

    # defaults when prompts are skipped
    base = validated[0][1] if validated else output_dir
    cache_dir = os.environ.get("AFO_CACHE_DIR") or os.path.join(base, "afo", "cache")
    store_dir = os.environ.get("AFO_STORE_DIR") or os.path.join(base, "afo", "store")
    tmp_dir = os.environ.get("AFO_TMPDIR") or os.path.join(base, "afo", "tmp")
    create_symlinks = os.path.abspath(base) != os.path.abspath(output_dir)
    disk_budget = parse_size(os.environ.get("AFO_DISK_BUDGET", ""))
    stop_low = True

    if interactive:
        try:
            if candidate_info:
                table = Table("Mount", "Free (GB)", "Status")
                for avail, mount, ok, reason in candidate_info[:3]:
                    status = "✅ Validated" if ok else f"❌ {reason}"
                    table.add_row(mount, f"{avail/1024**3:.1f}", status)
                console.print(table)
                if skipped_msgs and validated:
                    console.print(
                        f"Auto-skipped: {', '.join(skipped_msgs)}. Using: {validated[0][1]} (validated)."
                    )
                elif skipped_msgs and not validated:
                    console.print(
                        f"Auto-skipped: {', '.join(skipped_msgs)}. No valid mount found; using output directory."
                    )

            if not (
                os.environ.get("AFO_CACHE_DIR")
                or os.environ.get("AFO_STORE_DIR")
                or os.environ.get("AFO_TMPDIR")
            ):
                use_best = Confirm.ask(
                    "Use the best mount for cache/store/tmp? (Y/n)", default=True
                )
            else:
                use_best = True

            if not use_best:
                cache_dir = Prompt.ask(
                    "Cache dir", default=os.path.join(output_dir, ".cache")
                )
                store_dir = Prompt.ask(
                    "Store dir", default=os.path.join(output_dir, ".store")
                )
                tmp_dir = Prompt.ask(
                    "Temp dir", default=tempfile.gettempdir()
                )
                cache_dir = os.path.abspath(os.path.expanduser(cache_dir))
                store_dir = os.path.abspath(os.path.expanduser(store_dir))
                tmp_dir = os.path.abspath(os.path.expanduser(tmp_dir))
            else:
                cache_dir = os.path.abspath(cache_dir)
                store_dir = os.path.abspath(store_dir)
                tmp_dir = os.path.abspath(tmp_dir)

            # validate paths
            ok, reason = validate_mount(cache_dir)
            while not ok:
                console.print(f"[red]Cache path invalid: {reason}[/]")
                cache_dir = os.path.abspath(
                    os.path.expanduser(
                        Prompt.ask(
                            "Cache dir", default=os.path.join(output_dir, ".cache")
                        )
                    )
                )
                ok, reason = validate_mount(cache_dir)
            ok, reason = validate_mount(store_dir)
            while not ok:
                console.print(f"[red]Store path invalid: {reason}[/]")
                store_dir = os.path.abspath(
                    os.path.expanduser(
                        Prompt.ask(
                            "Store dir", default=os.path.join(output_dir, ".store")
                        )
                    )
                )
                ok, reason = validate_mount(store_dir)
            ok, reason = validate_mount(tmp_dir)
            while not ok:
                console.print(f"[red]Temp path invalid: {reason}[/]")
                tmp_dir = os.path.abspath(
                    os.path.expanduser(
                        Prompt.ask("Temp dir", default=tempfile.gettempdir())
                    )
                )
                ok, reason = validate_mount(tmp_dir)

            if (
                os.path.commonpath([cache_dir, output_dir])
                != os.path.abspath(output_dir)
                or os.path.commonpath([store_dir, output_dir])
                != os.path.abspath(output_dir)
            ):
                create_symlinks = Confirm.ask(
                    f"Create symlinks .cache and .store inside {output_dir} pointing to the chosen locations? (Y/n)",
                    default=True,
                )
            else:
                create_symlinks = False

            if os.environ.get("AFO_DISK_BUDGET"):
                disk_budget = parse_size(os.environ["AFO_DISK_BUDGET"])
            else:
                while True:
                    val = Prompt.ask(
                        "Set a disk budget for all data (e.g. 1G, 2G). Leave empty for unlimited:",
                        default="",
                    )
                    disk_budget = parse_size(val)
                    if val == "" or disk_budget is not None:
                        break

            stop_low = Confirm.ask(
                "On low disk space, stop current repo gracefully and print summary? (Y/n)",
                default=True,
            )

            summary = Table("Target", "Path", "Mount", "Status")
            summary.add_row(
                "Output",
                output_dir,
                mount_point(output_dir),
                "✅",
            )
            summary.add_row("Cache", cache_dir, mount_point(cache_dir), "✅")
            summary.add_row("Store", store_dir, mount_point(store_dir), "✅")
            summary.add_row("Tmp", tmp_dir, mount_point(tmp_dir), "✅")
            console.print(summary)
            console.print(
                f"Disk budget: {'unlimited' if disk_budget is None else str(disk_budget)}"
            )

            if Confirm.ask(
                f"Save these settings to {config_path} for future runs? (Y/n)",
                default=True,
            ):
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "cache_dir": cache_dir,
                            "store_dir": store_dir,
                            "tmp_dir": tmp_dir,
                            "disk_budget": disk_budget,
                            "stop_on_low_space": stop_low,
                            "link_cache_store": create_symlinks,
                        },
                        f,
                        indent=2,
                    )
        except KeyboardInterrupt:
            console.print("[red]Setup cancelled[/]")
            raise SystemExit(1)
    else:
        cache_dir = os.path.abspath(cache_dir)
        store_dir = os.path.abspath(store_dir)
        tmp_dir = os.path.abspath(tmp_dir)
        for path, label in [(cache_dir, "cache"), (store_dir, "store"), (tmp_dir, "temp")]:
            ok, reason = validate_mount(path)
            if not ok:
                console.print(f"[red]{label} path invalid: {reason}[/]")
                raise SystemExit(1)

    config = {
        "cache_dir": cache_dir,
        "store_dir": store_dir,
        "tmp_dir": tmp_dir,
        "disk_budget": disk_budget,
        "stop_on_low_space": stop_low,
        "link_cache_store": create_symlinks,
    }

    if not interactive and (
        args.setup or (not os.path.exists(config_path) and not args.reset_config)
    ):
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    return output_dir, config


def setup_storage(
    templates_dir: str,
    logger: logging.Logger,
    cache_target: str,
    store_target: str,
    tmp_target: str,
    link_cache_store: bool,
) -> tuple[str, str, str, str]:
    """Ensure cache, store and tmp locations exist and return their paths."""

    cache_target = os.path.abspath(cache_target)
    store_target = os.path.abspath(store_target)
    tmp_target = os.path.abspath(tmp_target)

    if link_cache_store and os.path.abspath(cache_target) != os.path.join(
        templates_dir, ".cache"
    ):
        ensure_symlink(os.path.join(templates_dir, ".cache"), cache_target, logger)
        cache_dir = os.path.join(templates_dir, ".cache", "repos")
    else:
        os.makedirs(os.path.join(cache_target, "repos"), exist_ok=True)
        cache_dir = os.path.join(cache_target, "repos")

    if link_cache_store and os.path.abspath(store_target) != os.path.join(
        templates_dir, ".store"
    ):
        ensure_symlink(os.path.join(templates_dir, ".store"), store_target, logger)
        store_dir = os.path.join(templates_dir, ".store")
    else:
        os.makedirs(store_target, exist_ok=True)
        store_dir = store_target

    os.makedirs(tmp_target, exist_ok=True)
    os.environ["TMPDIR"] = tmp_target

    storage_root = os.path.realpath(store_dir)
    return cache_dir, store_dir, tmp_target, storage_root

def copy_yaml_file(
    source_path: str,
    rel_repo_path: str,
    repo_url: str,
    commit: str,
    dest_root: str,
    store_dir: str,
    content_index: dict,
    index_path: str,
    url_registry: dict,
    logger: logging.Logger,
) -> tuple[bool, bool]:
    """Store YAML content by hash and hard-link into destination.

    Returns tuple of (added, updated) booleans for the destination tree.
    """

    basename = os.path.basename(rel_repo_path)
    owner_repo = "/".join(urlparse(repo_url).path.strip("/").split("/")[:2])
    owner, repo = owner_repo.split("/")
    year = extract_cve_year(basename)
    dest_folder = os.path.join(dest_root, f"CVE-{year}" if year else "Vulnerability-Templates")
    ok, low = check_free_space([dest_root, os.path.realpath(store_dir)])
    if not ok:
        raise DiskSpaceError(low)
    os.makedirs(dest_folder, exist_ok=True)

    hash_val = compute_sha1(source_path)
    store_file = store_path(store_dir, hash_val)
    if not os.path.exists(store_file):
        tmp_store = store_file + ".part"
        shutil.copy2(source_path, tmp_store)
        os.replace(tmp_store, store_file)

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    raw_url = (
        f"{repo_url.replace('github.com', 'raw.githubusercontent.com')}/{commit}/{rel_repo_path.replace(os.sep, '/')}"
    )
    stat = os.stat(store_file)
    url_registry[repo_url].append(
        {
            "url": raw_url,
            "size": stat.st_size,
            "sha1": hash_val,
            "last_modified": "",
            "etag": "",
        }
    )

    if hash_val in content_index:
        for entry in content_index[hash_val]:
            entry["last_updated"] = now
        return False, False

    dest_name = basename
    dest_path = os.path.join(dest_folder, dest_name)
    rel_path = os.path.relpath(dest_path, os.path.dirname(index_path))

    # locate existing index entry for this path
    existing_hash = None
    existing_repo = None
    for h, entries in content_index.items():
        for e in entries:
            if e["path"] == rel_path:
                existing_hash = h
                existing_repo = e["repo_url"]
                break
        if existing_hash:
            break

    if existing_hash and existing_repo == repo_url:
        if existing_hash == hash_val:
            for e in content_index[existing_hash]:
                if e["path"] == rel_path and e["repo_url"] == repo_url:
                    e["last_updated"] = now
            return False, False
        # replace in place
        tmp_dest = dest_path + ".part"
        hardlink_or_copy(store_file, tmp_dest)
        os.replace(tmp_dest, dest_path)
        content_index[existing_hash] = [
            e for e in content_index[existing_hash] if not (e["path"] == rel_path and e["repo_url"] == repo_url)
        ]
        if not content_index[existing_hash]:
            del content_index[existing_hash]
        content_index.setdefault(hash_val, []).append(
            {"path": rel_path, "repo_url": repo_url, "first_seen": now, "last_updated": now}
        )
        return False, True

    if existing_hash and existing_repo != repo_url:
        dest_name = (
            f"{os.path.splitext(basename)[0]}__from-{sanitize_segment(owner)}-{sanitize_segment(repo)}__{hash_val[:8]}.yaml"
        )
        dest_path = os.path.join(dest_folder, dest_name)
        rel_path = os.path.relpath(dest_path, os.path.dirname(index_path))

    tmp_dest = dest_path + ".part"
    hardlink_or_copy(store_file, tmp_dest)
    os.replace(tmp_dest, dest_path)

    content_index.setdefault(hash_val, []).append(
        {"path": rel_path, "repo_url": repo_url, "first_seen": now, "last_updated": now}
    )
    return True, False


def request_cancel(signum, frame) -> None:
    """Signal handler for graceful shutdown."""
    global CANCEL_REQUESTED
    if not CANCEL_REQUESTED:
        CANCEL_REQUESTED = True
        logging.getLogger("collector").info("Cancellation requested by user")
        console.print(
            "[yellow]تم طلب الإلغاء… جاري التنظيف وكتابة الملخّص. يمكنك إعادة التشغيل للاستئناف.[/]"
        )


def setup_logger(log_path: str) -> logging.Logger:
    """Create a file logger writing to ``log_path``."""

    logger = logging.getLogger("collector")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
    )

    logger.addHandler(file_handler)
    return logger


def git_clone(url: str, destination: str) -> tuple[int, str]:
    """Clone a git repository to ``destination`` and return result code and stderr."""

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", "clone", url, destination],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )
    return result.returncode, result.stderr.decode().strip()


def generate_destination_folder(url: str, base_dir: str) -> str:
    folder_name = os.path.basename(url.rstrip("/"))
    counter = 1
    while os.path.exists(os.path.join(base_dir, folder_name)):
        folder_name = f"{os.path.basename(url.rstrip('/'))}_{counter}"
        counter += 1
    return folder_name


def extract_cve_year(file_name: str) -> str | None:
    if file_name.startswith("CVE-") and file_name[4:8].isdigit():
        return file_name[4:8]
    return None


def count_yaml_files(folder: str) -> int:
    count = 0
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".yaml"):
                count += 1
    return count


def cleanup_temp(templates_dir: str) -> None:
    """Remove temporary working folders and partial files."""
    shutil.rmtree(os.path.join(templates_dir, "TRASH"), ignore_errors=True)
    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith(".part"):
                os.remove(os.path.join(root, file))


def cleanup_store(store_dir: str, content_index: dict) -> int:
    """Remove unreferenced blobs from content store."""

    keep = set(content_index.keys())
    removed = 0
    for prefix in os.listdir(store_dir):
        subdir = os.path.join(store_dir, prefix)
        if not os.path.isdir(subdir):
            continue
        for fname in os.listdir(subdir):
            if not fname.endswith(".yaml"):
                continue
            h = fname[:-5]
            if h not in keep:
                try:
                    os.remove(os.path.join(subdir, fname))
                    removed += 1
                except OSError:
                    pass
    return removed


def wait_countdown(seconds: int, message: str, spinner: str = "clock") -> None:
    """Display a countdown with spinner for waits/backoffs."""

    status = console.status(f"{message} {seconds:02d}s", spinner=spinner)
    status.start()
    try:
        for remaining in range(seconds, 0, -1):
            if CANCEL_REQUESTED:
                break
            status.update(f"{message} {remaining:02d}s")
            time.sleep(1)
    finally:
        status.stop()


def summarize_templates(templates_dir: str) -> None:
    cve_folders = glob.glob(os.path.join(templates_dir, "CVE-*"))
    cve_yaml_count = sum(count_yaml_files(folder) for folder in cve_folders)

    vulnerability_folder = os.path.join(templates_dir, "Vulnerability-Templates")
    vuln_yaml_count = count_yaml_files(vulnerability_folder)

    total_yaml_count = cve_yaml_count + vuln_yaml_count

    table = Table(title="Template Summary")
    table.add_column("Template Type")
    table.add_column("Count", justify="right")
    table.add_row("CVE Templates", str(cve_yaml_count))
    table.add_row("Other Vulnerability Templates", str(vuln_yaml_count))
    table.add_row("Total Templates", str(total_yaml_count))

    console.print(table)


def show_confetti(duration: float = 2.0) -> None:
    """Display a simple text confetti animation."""

    colors = ["red", "green", "yellow", "blue", "magenta", "cyan"]
    end = time.time() + duration
    while time.time() < end:
        line = "".join(random.choice(["✨", "🎉", "💥"]) for _ in range(20))
        console.print(line, style=random.choice(colors))
        time.sleep(0.1)

    return


def clone_repositories(
    file_url: str,
    templates_dir: str,
    cache_dir: str,
    logger: logging.Logger,
    manifest: dict,
    content_index: dict,
    index_path: str,
    counters: dict,
    url_registry: dict,
    store_dir: str,
    storage_root: str,
) -> tuple[list[str], list[str], list[str]]:
    """Fetch repositories and update templates incrementally."""
    global CANCEL_REQUESTED
    logger.info(f"Fetching repository list from: {file_url}")
    try:
        resp = requests.get(file_url, timeout=30)
        resp.raise_for_status()
        raw = [r.strip() for r in resp.text.splitlines() if r.strip()]
    except requests.RequestException as exc:
        logger.error(f"Failed to retrieve repository list: {exc}")
        return [], [], []
    repos: list[str] = []
    for r in raw:
        n = normalize_repo_url(r)
        if n not in repos:
            repos.append(n)
    repo_prog = Progress(
        AnimatedSpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=False,
        refresh_per_second=10,
    )
    sum_prog = Progress(
        BarColumn(),
        TextColumn(
            "Updated:{task.fields[u]} | Up-to-date:{task.fields[d]} | Skipped:{task.fields[s]} | Failed:{task.fields[f]} | Active:{task.fields[a]} | Queue:{task.fields[q]} |"
        ),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        refresh_per_second=10,
    )
    sum_task = sum_prog.add_task("overall", total=len(repos), u=0, d=0, s=0, f=0, a=0, q=len(repos))
    succ: list[str] = []
    skip: list[str] = []
    fail: list[str] = []
    group = Group(sum_prog, repo_prog)
    with Live(group, console=console, refresh_per_second=10):
        for repo in repos:
            if CANCEL_REQUESTED:
                break
            a = sum_prog.tasks[0].fields["a"] + 1
            q = sum_prog.tasks[0].fields["q"] - 1
            sum_prog.update(sum_task, a=a, q=q)
            name = repo.split("/")[-1]
            cache = repo_cache_path(repo, cache_dir)
            t = repo_prog.add_task(f"{name} HEAD", spinner=STATE_SPINNERS["head"])
            try:
                h = requests.head(repo, allow_redirects=True, timeout=15)
                code = h.status_code
                logger.info(f"HEAD {repo} -> {code}")
                if code in (404, 410):
                    skip.append(repo)
                    repo_prog.update(
                        t,
                        description=f"{name} {STATUS_ICONS['skipped']} 404",
                        total=1,
                        completed=1,
                    )
                    repo_prog.remove_task(t)
                    s = sum_prog.tasks[0].fields["s"] + 1
                    a = sum_prog.tasks[0].fields["a"] - 1
                    sum_prog.advance(sum_task)
                    sum_prog.update(sum_task, s=s, a=a)
                    manifest.setdefault("repos", {})[repo] = {
                        "url": repo,
                        "status": "skipped",
                        "deprecated": True,
                        "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    }
                    manifest.setdefault("deprecated_repos", []).append(repo)
                    continue
                if not (200 <= code < 400):
                    raise requests.RequestException(f"HEAD returned {code}")
            except requests.RequestException as exc:
                logger.warning(f"HEAD {repo} failed: {exc}")
                fail.append(repo)
                repo_prog.update(
                    t,
                    description=f"{name} {STATUS_ICONS['failed']}",
                    total=1,
                    completed=1,
                )
                repo_prog.remove_task(t)
                f = sum_prog.tasks[0].fields["f"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, f=f, a=a)
                manifest.setdefault("repos", {})[repo] = {
                    "url": repo,
                    "status": "failed",
                    "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                continue
            if CANCEL_REQUESTED:
                repo_prog.remove_task(t)
                break
            ok, low = check_free_space([templates_dir, storage_root])
            if not ok:
                console.print(f"[red]Low disk space on {low}[/]")
                logger.warning(f"Low disk space on {low}; skipping {repo}")
                skip.append(repo)
                repo_prog.update(
                    t,
                    description=f"{name} {STATUS_ICONS['skipped']} low space",
                    total=1,
                    completed=1,
                )
                repo_prog.remove_task(t)
                s = sum_prog.tasks[0].fields["s"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, s=s, a=a)
                manifest.setdefault("repos", {})[repo] = {
                    "url": repo,
                    "status": "skipped",
                    "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                continue
            if os.path.isdir(cache):
                repo_prog.update(t, description=f"{name} pull", spinner=STATE_SPINNERS["clone"])
                r = subprocess.run(["git", "-C", cache, "pull", "--ff-only"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            else:
                os.makedirs(cache, exist_ok=True)
                repo_prog.update(t, description=f"{name} clone", spinner=STATE_SPINNERS["clone"])
                r = subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", repo, cache], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            logger.info(r.stdout.decode())
            if r.returncode != 0:
                fail.append(repo)
                repo_prog.update(t, description=f"{name} {STATUS_ICONS['failed']}", total=1, completed=1)
                repo_prog.remove_task(t)
                f = sum_prog.tasks[0].fields["f"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, f=f, a=a)
                manifest.setdefault("repos", {})[repo] = {
                    "url": repo,
                    "status": "failed",
                    "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                continue
            try:
                last_commit = subprocess.check_output(["git", "-C", cache, "rev-parse", "HEAD"]).decode().strip()
            except subprocess.SubprocessError:
                last_commit = ""
            repo_prog.update(
                t,
                description=f"[blue]{name} {STATUS_ICONS['updating']} +0 ~0",
                spinner=STATE_SPINNERS["copy"],
            )
            url_registry[repo] = []
            add = upd = 0
            try:
                for root, _, files in os.walk(cache):
                    for f in files:
                        if f.endswith(".yaml"):
                            src = os.path.join(root, f)
                            rel_repo_path = os.path.relpath(src, cache)
                            a2, u2 = copy_yaml_file(
                                src,
                                rel_repo_path,
                                repo,
                                last_commit,
                                templates_dir,
                                store_dir,
                                content_index,
                                index_path,
                                url_registry,
                                logger,
                            )
                            if a2:
                                add += 1
                                counters["added"] += 1
                            if u2:
                                upd += 1
                                counters["updated"] += 1
                            repo_prog.update(
                                t,
                                description=f"[blue]{name} {STATUS_ICONS['updating']} +{add} ~{upd}",
                            )
            except DiskSpaceError as dse:
                console.print(f"[red]Low disk space on {dse.path}[/]")
                logger.warning(f"Low disk space on {dse.path}; skipping {repo}")
                skip.append(repo)
                repo_prog.update(
                    t,
                    description=f"{name} {STATUS_ICONS['skipped']} low space",
                    total=1,
                    completed=1,
                )
                repo_prog.remove_task(t)
                s = sum_prog.tasks[0].fields["s"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, s=s, a=a)
                manifest.setdefault("repos", {})[repo] = {
                    "url": repo,
                    "status": "skipped",
                    "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                continue
            if add == 0 and upd == 0:
                repo_prog.update(
                    t,
                    description=f"[green]{name} {STATUS_ICONS['up_to_date']}",
                    total=1,
                    completed=1,
                    spinner=STATE_SPINNERS["done"],
                )
                succ.append(repo)
                status = "up-to-date"
                d = sum_prog.tasks[0].fields["d"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, d=d, a=a)
            else:
                repo_prog.update(
                    t,
                    description=f"[green]{name} {STATUS_ICONS['updating']} +{add} ~{upd}",
                    total=1,
                    completed=1,
                    spinner=STATE_SPINNERS["done"],
                )
                succ.append(repo)
                status = "updated"
                u = sum_prog.tasks[0].fields["u"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, u=u, a=a)
            repo_prog.remove_task(t)
            manifest.setdefault("repos", {})[repo] = {
                "url": repo,
                "method": "git",
                "last_commit": last_commit,
                "updated_files_count": add + upd,
                "last_checked": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": status,
            }
    return succ, skip, fail

def banner() -> None:
    console.print("[bold magenta]Nuclei Template Collector[/]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Nuclei templates from public repositories."
    )
    parser.add_argument(
        "--repo-list-url",
        default="https://raw.githubusercontent.com/AggressiveUser/AllForOne/main/PleaseUpdateMe.txt",
        help="URL pointing to list of repositories.",
    )
    parser.add_argument(
        "--output-dir",
        default="Templates",
        help="Directory to store collected templates.",
    )
    parser.add_argument(
        "--temp-dir",
        help="Use this directory for cache/store/tmp instead of auto selection.",
    )
    parser.add_argument(
        "--save-success-list",
        metavar="PATH",
        help="Save successfully cloned repository URLs to this file.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Run initial setup wizard.",
    )
    parser.add_argument(
        "--reset-config",
        action="store_true",
        help="Ignore saved configuration for this run.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Assume defaults and run non-interactively.",
    )
    args = parser.parse_args()

    output_dir, config = run_setup(args)

    banner()
    templates_dir = os.path.abspath(output_dir)
    os.makedirs(templates_dir, exist_ok=True)

    log_path = os.path.join(templates_dir, "run.log")
    logger = setup_logger(log_path)
    signal.signal(signal.SIGINT, request_cancel)
    logger.info(
        "output_dir=%s cache_dir=%s store_dir=%s tmp_dir=%s disk_budget=%s stop_on_low_space=%s link_cache_store=%s",
        templates_dir,
        config["cache_dir"],
        config["store_dir"],
        config["tmp_dir"],
        config["disk_budget"],
        config["stop_on_low_space"],
        config["link_cache_store"],
    )
    if args.temp_dir:
        base = os.path.abspath(args.temp_dir)
        config["cache_dir"] = os.path.join(base, "afo", "cache")
        config["store_dir"] = os.path.join(base, "afo", "store")
        config["tmp_dir"] = os.path.join(base, "afo", "tmp")
        config["link_cache_store"] = True
    if config.get("disk_budget") is not None:
        os.environ["AFO_DISK_BUDGET"] = str(config["disk_budget"])

    manifest_path = os.path.join(templates_dir, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    else:
        manifest = {"repos": {}, "deprecated_repos": []}
    manifest.setdefault("repos", {})
    manifest.setdefault("deprecated_repos", [])

    index_path = os.path.join(templates_dir, "content-index.json")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            raw_index = json.load(f)
        content_index = {}
        for h, entries in raw_index.items():
            # migrate older list-based schema
            if entries and isinstance(entries, list) and entries and isinstance(entries[0], str):
                path, repo_url, first_seen, last_updated = entries
                content_index[h] = [
                    {
                        "path": path,
                        "repo_url": repo_url,
                        "first_seen": first_seen,
                        "last_updated": last_updated,
                    }
                ]
            else:
                content_index[h] = entries
    else:
        content_index = {}

    url_registry_path = os.path.join(templates_dir, "url-registry.json")
    if os.path.exists(url_registry_path):
        with open(url_registry_path, "r", encoding="utf-8") as f:
            url_registry = json.load(f)
    else:
        url_registry = {}

    cache_dir, store_dir, tmp_dir, storage_root = setup_storage(
        templates_dir,
        logger,
        config["cache_dir"],
        config["store_dir"],
        config["tmp_dir"],
        config["link_cache_store"],
    )

    counters = {"added": 0, "updated": 0}

    success_repos: list[str] = []
    skipped_repos: list[str] = []
    failed_repos: list[str] = []
    removed_blobs = 0

    try:
        success_repos, skipped_repos, failed_repos = clone_repositories(
            args.repo_list_url,
            templates_dir,
            cache_dir,
            logger,
            manifest,
            content_index,
            index_path,
            counters,
            url_registry,
            store_dir,
            storage_root,
        )
        removed_blobs = cleanup_store(store_dir, content_index)
        summarize_templates(templates_dir)
    finally:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(content_index, f, indent=2)
        with open(url_registry_path, "w", encoding="utf-8") as f:
            json.dump(url_registry, f, indent=2)
        cleanup_temp(templates_dir)

    if CANCEL_REQUESTED:
        console.print("[bold red]Goodbye[/]")
        wait_countdown(2, "تنظيف…", STATE_SPINNERS["cleanup"])
    else:
        show_confetti()

    if args.save_success_list:
        success_path = os.path.abspath(args.save_success_list)
        with open(success_path, "w", encoding="utf-8") as f:
            f.write("\n".join(success_repos))
        console.print(f"[green]Successful repositories saved to [bold]{success_path}[/]")
    else:
        success_path = None

    updated_count = sum(1 for r in success_repos if manifest["repos"][r]["status"] == "updated")
    up_to_date_count = sum(1 for r in success_repos if manifest["repos"][r]["status"] == "up-to-date")

    console.print("\n[bold]Repository statistics[/]")
    stats_table = Table(show_header=False)
    stats_table.add_row("Updated repos", str(updated_count))
    stats_table.add_row("Up-to-date repos", str(up_to_date_count))
    stats_table.add_row("Skipped (404)", str(len(skipped_repos)))
    stats_table.add_row("Failed", str(len(failed_repos)))
    stats_table.add_row("Added YAMLs", str(counters["added"]))
    stats_table.add_row("Changed YAMLs", str(counters["updated"]))
    stats_table.add_row("removed_orphaned_blobs", str(removed_blobs))
    stats_table.add_row("run.log", log_path)
    stats_table.add_row("manifest", manifest_path)
    stats_table.add_row("content-index", index_path)
    stats_table.add_row("url-registry", url_registry_path)
    if success_path:
        stats_table.add_row("success list", success_path)
    console.print(stats_table)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

