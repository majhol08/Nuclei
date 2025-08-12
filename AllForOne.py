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

import requests
from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table


console = Console()
CANCEL_REQUESTED = False


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


def clone_repositories(
    file_url: str,
    templates_dir: str,
    logger: logging.Logger,
    success_repos: list[str],
    skipped_repos: list[str],
    failed_repos: list[str],
    zip_fallback: list[str],
) -> None:
    """Clone repositories listed at ``file_url`` into ``templates_dir``."""

    logger.info(f"Fetching repository list from: {file_url}")
    try:
        response = requests.get(file_url, timeout=30)
        response.raise_for_status()
        repositories = [
            r for r in response.text.strip().split("\n") if r and r not in success_repos
        ]
    except requests.RequestException as exc:
        logger.error(f"Failed to retrieve repository list: {exc}")
        return

    trash_dir = os.path.join(templates_dir, "TRASH")
    os.makedirs(trash_dir, exist_ok=True)

    repo_progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=False,
        refresh_per_second=10,
    )

    summary_progress = Progress(
        BarColumn(),
        TextColumn(
            "Successful: {task.fields[success]} | Skipped: {task.fields[skipped]} | Failed: {task.fields[failed]} | Active: {task.fields[active]} | Queue: {task.fields[queue]} |",
        ),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        refresh_per_second=10,
    )

    total_repos = len(repositories) + len(success_repos) + len(skipped_repos) + len(failed_repos)
    success = len(success_repos)
    skipped = len(skipped_repos)
    failed = len(failed_repos)
    active = 0
    queue = len(repositories)
    summary_task = summary_progress.add_task(
        "overall",
        total=total_repos,
        completed=success + skipped + failed,
        success=success,
        skipped=skipped,
        failed=failed,
        active=0,
        queue=queue,
    )

    group = Group(summary_progress, repo_progress)

    with Live(group, console=console, refresh_per_second=10):
        for repo in repositories:
            if CANCEL_REQUESTED:
                break
            queue -= 1
            active += 1
            summary_progress.update(
                summary_task,
                success=success,
                skipped=skipped,
                failed=failed,
                active=active,
                queue=queue,
            )

            name = repo.split("/")[-1]
            task = repo_progress.add_task(f"{name} HEAD", total=None)
            logger.info(f"HEAD {repo}")
            try:
                resp = requests.head(repo, allow_redirects=True, timeout=15)
                logger.info(f"HEAD {repo} -> {resp.status_code}")
                if resp.status_code == 404:
                    skipped_repos.append(repo)
                    repo_progress.update(task, description=f"{name} skipped 404", total=1, completed=1)
                    repo_progress.remove_task(task)
                    active -= 1
                    skipped += 1
                    summary_progress.advance(summary_task)
                    summary_progress.update(
                        summary_task,
                        success=success,
                        skipped=skipped,
                        failed=failed,
                        active=active,
                        queue=queue,
                    )
                    continue
            except requests.RequestException as exc:
                logger.warning(f"HEAD {repo} failed: {exc}")
                skipped_repos.append(repo)
                repo_progress.update(task, description=f"{name} skipped", total=1, completed=1)
                repo_progress.remove_task(task)
                active -= 1
                skipped += 1
                summary_progress.advance(summary_task)
                summary_progress.update(
                    summary_task,
                    success=success,
                    skipped=skipped,
                    failed=failed,
                    active=active,
                    queue=queue,
                )
                continue

            if CANCEL_REQUESTED:
                repo_progress.update(task, description=f"{name} cancelled", total=1, completed=1)
                repo_progress.remove_task(task)
                active -= 1
                break

            attempt = 1
            destination = os.path.join(trash_dir, generate_destination_folder(repo, trash_dir))
            cloned = False
            while attempt <= 2 and not cloned:
                if CANCEL_REQUESTED:
                    break
                logger.info(f"Clone attempt #{attempt} {repo}")
                repo_progress.update(task, description=f"{name} clone #{attempt}")
                return_code, error = git_clone(repo, destination)
                if return_code == 0:
                    logger.info(f"Clone success {repo}")
                    cloned = True
                    break
                logger.warning(f"Clone failed {repo}: {error}")
                attempt += 1
                if attempt <= 2:
                    repo_progress.update(task, description=f"{name} retry #{attempt}")
                    logger.info(f"Retrying {repo} in 3s")
                    for _ in range(3):
                        if CANCEL_REQUESTED:
                            break
                        time.sleep(1)
                    if CANCEL_REQUESTED:
                        break

            if not cloned and not CANCEL_REQUESTED:
                logger.info(f"Falling back to zip for {repo}")
                repo_progress.update(task, description=f"{name} zip", total=None, completed=0)
                zip_urls = [
                    f"{repo}/archive/refs/heads/main.zip",
                    f"{repo}/archive/refs/heads/master.zip",
                ]
                for url in zip_urls:
                    if CANCEL_REQUESTED:
                        break
                    try:
                        with requests.get(url, stream=True, timeout=30) as r:
                            r.raise_for_status()
                            total = int(r.headers.get("Content-Length", 0))
                            if total:
                                repo_progress.update(task, total=total, completed=0)
                            zip_path = destination + ".zip"
                            with open(zip_path, "wb") as f:
                                for chunk in r.iter_content(chunk_size=8192):
                                    f.write(chunk)
                                    repo_progress.advance(task, len(chunk))
                            shutil.unpack_archive(zip_path, destination)
                            os.remove(zip_path)
                            zip_fallback.append(repo)
                            cloned = True
                            logger.info(f"ZIP fallback success {repo}")
                            break
                    except requests.RequestException as exc:
                        logger.warning(f"ZIP download failed {url}: {exc}")
                    except (shutil.ReadError, FileNotFoundError) as exc:
                        logger.warning(f"ZIP extract failed {repo}: {exc}")

            if CANCEL_REQUESTED and not cloned:
                repo_progress.update(task, description=f"{name} cancelled", total=1, completed=1)
                repo_progress.remove_task(task)
                active -= 1
                break

            if not cloned:
                failed_repos.append(repo)
                repo_progress.update(task, description=f"{name} failed", total=1, completed=1)
                repo_progress.remove_task(task)
                active -= 1
                failed += 1
                summary_progress.advance(summary_task)
                summary_progress.update(
                    summary_task,
                    success=success,
                    skipped=skipped,
                    failed=failed,
                    active=active,
                    queue=queue,
                )
                continue

            repo_progress.update(task, description=f"{name} copy", total=None)
            copied = 0
            for root, _, files in os.walk(destination):
                if CANCEL_REQUESTED:
                    break
                for file in files:
                    if CANCEL_REQUESTED:
                        break
                    if file.endswith(".yaml"):
                        source_path = os.path.join(root, file)
                        cve_year = extract_cve_year(file)
                        if cve_year:
                            dest_folder = os.path.join(templates_dir, f"CVE-{cve_year}")
                        else:
                            dest_folder = os.path.join(templates_dir, "Vulnerability-Templates")
                        os.makedirs(dest_folder, exist_ok=True)
                        try:
                            tmp_dest = os.path.join(dest_folder, file + ".part")
                            shutil.copy2(source_path, tmp_dest)
                            os.replace(tmp_dest, os.path.join(dest_folder, file))
                            copied += 1
                        except OSError as exc:
                            if exc.errno == errno.ENOSPC:
                                logger.error(
                                    f"No space left on device while copying {file}. Aborting.",
                                )
                            else:
                                logger.error(f"Failed to copy {file}: {exc.strerror or exc}")
                            shutil.rmtree(trash_dir, ignore_errors=True)
                            return
                if CANCEL_REQUESTED:
                    break
            if CANCEL_REQUESTED:
                repo_progress.update(task, description=f"{name} cancelled", total=1, completed=1)
                repo_progress.remove_task(task)
                active -= 1
                break
            logger.info(f"Copied {copied} templates from {repo}")
            success_repos.append(repo)
            shutil.rmtree(destination, ignore_errors=True)
            repo_progress.update(task, description=f"{name} done", total=1, completed=1)
            repo_progress.remove_task(task)
            active -= 1
            success += 1
            summary_progress.advance(summary_task)
            summary_progress.update(
                summary_task,
                success=success,
                skipped=skipped,
                failed=failed,
                active=active,
                queue=queue,
            )

    shutil.rmtree(trash_dir, ignore_errors=True)
    return


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
        manifest = {"successful": [], "skipped": [], "failed": [], "zip_used": []}

    success_repos = manifest["successful"]
    skipped_repos = manifest["skipped"]
    failed_repos = manifest["failed"]
    zip_used = manifest.get("zip_used", [])

    try:
        clone_repositories(
            args.repo_list_url,
            templates_dir,
            logger,
            success_repos,
            skipped_repos,
            failed_repos,
            zip_used,
        )
        summarize_templates(templates_dir)
    finally:
        manifest = {
            "successful": success_repos,
            "skipped": skipped_repos,
            "failed": failed_repos,
            "zip_used": zip_used,
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        cleanup_temp(templates_dir)

    if args.save_success_list:
        success_path = os.path.abspath(args.save_success_list)
        with open(success_path, "w", encoding="utf-8") as f:
            f.write("\n".join(success_repos))
        console.print(f"[green]Successful repositories saved to [bold]{success_path}[/]")
    else:
        success_path = None

    console.print("\n[bold]Repository statistics[/]")
    stats_table = Table(show_header=False)
    stats_table.add_row("Successful", str(len(success_repos)))
    stats_table.add_row("Skipped", str(len(skipped_repos)))
    stats_table.add_row("Failed", str(len(failed_repos)))
    stats_table.add_row("ZIP Fallback", str(len(zip_used)))
    stats_table.add_row("run.log", log_path)
    stats_table.add_row("manifest", manifest_path)
    if success_path:
        stats_table.add_row("success list", success_path)
    console.print(stats_table)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

