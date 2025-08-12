"""Nuclei template collector with rich progress and logging."""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import shutil
import signal
import subprocess
import time
import errno
import random
import datetime
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


def ensure_disk_space(path: str, threshold: int = 1_000_000_000) -> bool:
    """Return True if free space above threshold (default 1GB)."""
    usage = shutil.disk_usage(path)
    if usage.free < threshold:
        console.print("[red]Insufficient disk space (<1GB). Aborting.[/]")
        return False
    return True


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


def clone_repositories(file_url: str, templates_dir: str, cache_dir: str, logger: logging.Logger, manifest: dict, content_index: dict, index_path: str, counters: dict, url_registry: dict, store_dir: str) -> tuple[list[str], list[str], list[str]]:
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
            if not ensure_disk_space(templates_dir):
                CANCEL_REQUESTED = True
                break
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
        "--save-success-list",
        metavar="PATH",
        help="Save successfully cloned repository URLs to this file.",
    )
    args = parser.parse_args()

    banner()
    templates_dir = os.path.abspath(args.output_dir)
    os.makedirs(templates_dir, exist_ok=True)

    log_path = os.path.join(templates_dir, "run.log")
    logger = setup_logger(log_path)
    signal.signal(signal.SIGINT, request_cancel)

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

    cache_dir = os.path.join(templates_dir, ".cache", "repos")
    os.makedirs(cache_dir, exist_ok=True)
    store_dir = os.path.join(templates_dir, ".store")
    os.makedirs(store_dir, exist_ok=True)

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

