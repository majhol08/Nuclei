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
from datetime import datetime
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


def ensure_disk_space(path: str, threshold: int = 1_000_000_000) -> bool:
    """Return True if free space above threshold (default 1GB)."""
    usage = shutil.disk_usage(path)
    if usage.free < threshold:
        console.print("[red]Insufficient disk space (<1GB). Aborting.[/]")
        return False
    return True


def copy_yaml_file(
    source_path: str,
    dest_folder: str,
    repo_url: str,
    content_index: dict,
    index_path: str,
    logger: logging.Logger,
) -> tuple[bool, bool]:
    """Copy ``source_path`` into ``dest_folder`` with de-duplication.

    Returns tuple of (added, updated) booleans.
    """

    file = os.path.basename(source_path)
    os.makedirs(dest_folder, exist_ok=True)
    dest_path = os.path.join(dest_folder, file)
    hash_val = compute_sha1(source_path)

    entry = content_index.get(hash_val)
    if entry:
        # content already exists somewhere; skip copying
        entry[3] = datetime.utcnow().isoformat()
        content_index[hash_val] = entry
        return False, False

    added = False
    updated = False
    if os.path.exists(dest_path):
        # compare existing file
        stat_src = os.stat(source_path)
        stat_dst = os.stat(dest_path)
        if stat_src.st_size == stat_dst.st_size and int(stat_src.st_mtime) == int(
            stat_dst.st_mtime
        ):
            dst_hash = compute_sha1(dest_path)
            if dst_hash == hash_val:
                return False, False
        tmp_dest = dest_path + ".part"
        shutil.copy2(source_path, tmp_dest)
        os.replace(tmp_dest, dest_path)
        updated = True
    else:
        tmp_dest = dest_path + ".part"
        shutil.copy2(source_path, tmp_dest)
        os.replace(tmp_dest, dest_path)
        added = True

    rel_path = os.path.relpath(dest_path, os.path.dirname(index_path))
    content_index[hash_val] = [
        rel_path,
        repo_url,
        datetime.utcnow().isoformat(),
        datetime.utcnow().isoformat(),
    ]

    return added, updated


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


def clone_repositories(file_url: str, templates_dir: str, cache_dir: str, logger: logging.Logger, manifest: dict, content_index: dict, index_path: str, counters: dict) -> tuple[list[str], list[str], list[str]]:
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
    repo_prog = Progress(AnimatedSpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console, transient=False, refresh_per_second=10)
    sum_prog = Progress(BarColumn(), TextColumn("Updated:{task.fields[u]} | Up-to-date:{task.fields[d]} | Skipped:{task.fields[s]} | Failed:{task.fields[f]} | Active:{task.fields[a]} | Queue:{task.fields[q]} |"), TimeRemainingColumn(), console=console, transient=False, refresh_per_second=10)
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
                if code == 404:
                    skip.append(repo)
                    repo_prog.update(t, description=f"{name} {STATUS_ICONS['skipped']} 404", total=1, completed=1)
                    repo_prog.remove_task(t)
                    s = sum_prog.tasks[0].fields["s"] + 1
                    a = sum_prog.tasks[0].fields["a"] - 1
                    sum_prog.advance(sum_task)
                    sum_prog.update(sum_task, s=s, a=a)
                    manifest.setdefault("repos", {})[repo] = {"url": repo, "status": "skipped", "last_checked": datetime.utcnow().isoformat()}
                    continue
            except requests.RequestException as exc:
                logger.warning(f"HEAD {repo} failed: {exc}")
                skip.append(repo)
                repo_prog.update(t, description=f"{name} {STATUS_ICONS['skipped']}", total=1, completed=1)
                repo_prog.remove_task(t)
                s = sum_prog.tasks[0].fields["s"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, s=s, a=a)
                manifest.setdefault("repos", {})[repo] = {"url": repo, "status": "skipped", "last_checked": datetime.utcnow().isoformat()}
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
                manifest.setdefault("repos", {})[repo] = {"url": repo, "status": "failed", "last_checked": datetime.utcnow().isoformat()}
                continue
            if not ensure_disk_space(templates_dir):
                CANCEL_REQUESTED = True
                break
            repo_prog.update(t, description=f"{name} copy", spinner=STATE_SPINNERS["copy"])
            add = upd = 0
            for root, _, files in os.walk(cache):
                for f in files:
                    if f.endswith(".yaml"):
                        src = os.path.join(root, f)
                        year = extract_cve_year(f)
                        dest = os.path.join(templates_dir, f"CVE-{year}" if year else "Vulnerability-Templates")
                        a2, u2 = copy_yaml_file(src, dest, repo, content_index, index_path, logger)
                        if a2:
                            add += 1
                            counters["added"] += 1
                        if u2:
                            upd += 1
                            counters["updated"] += 1
            try:
                last_commit = subprocess.check_output(["git", "-C", cache, "rev-parse", "HEAD"]).decode().strip()
            except subprocess.SubprocessError:
                last_commit = ""
            if add == 0 and upd == 0:
                repo_prog.update(t, description=f"{name} {STATUS_ICONS['up_to_date']}", total=1, completed=1, spinner=STATE_SPINNERS["done"])
                succ.append(repo)
                status = "up-to-date"
                d = sum_prog.tasks[0].fields["d"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, d=d, a=a)
            else:
                repo_prog.update(t, description=f"{name} {STATUS_ICONS['updating']} +{add + upd}", total=1, completed=1, spinner=STATE_SPINNERS["done"])
                succ.append(repo)
                status = "updated"
                u = sum_prog.tasks[0].fields["u"] + 1
                a = sum_prog.tasks[0].fields["a"] - 1
                sum_prog.advance(sum_task)
                sum_prog.update(sum_task, u=u, a=a)
            repo_prog.remove_task(t)
            manifest.setdefault("repos", {})[repo] = {"url": repo, "method": "git", "last_commit": last_commit, "updated_files_count": add + upd, "last_checked": datetime.utcnow().isoformat(), "status": status}
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
        manifest = {"repos": {}}

    index_path = os.path.join(templates_dir, "content-index.json")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            content_index = json.load(f)
    else:
        content_index = {}

    cache_dir = os.path.join(templates_dir, ".cache", "repos")
    os.makedirs(cache_dir, exist_ok=True)

    counters = {"added": 0, "updated": 0}

    success_repos: list[str] = []
    skipped_repos: list[str] = []
    failed_repos: list[str] = []

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
        )
        summarize_templates(templates_dir)
    finally:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(content_index, f, indent=2)
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
    stats_table.add_row("Skipped", str(len(skipped_repos)))
    stats_table.add_row("Failed", str(len(failed_repos)))
    stats_table.add_row("Added YAMLs", str(counters["added"]))
    stats_table.add_row("Updated YAMLs", str(counters["updated"]))
    stats_table.add_row("run.log", log_path)
    stats_table.add_row("manifest", manifest_path)
    stats_table.add_row("content-index", index_path)
    if success_path:
        stats_table.add_row("success list", success_path)
    console.print(stats_table)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

