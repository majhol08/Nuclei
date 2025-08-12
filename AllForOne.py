"""Nuclei template collector with rich progress and logging."""

from __future__ import annotations

import argparse
import glob
import logging
import os
import shutil
import subprocess
import time
import errno

import requests
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table


console = Console()


def setup_logger(log_path: str) -> logging.Logger:
    """Create a logger printing to console and writing to ``log_path``."""

    logger = logging.getLogger("collector")
    logger.setLevel(logging.INFO)

    rich_handler = RichHandler(console=console, show_level=False, markup=True)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))

    file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
    )

    logger.addHandler(rich_handler)
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
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Clone repositories listed at ``file_url`` into ``templates_dir``."""

    logger.info(f"Fetching repository list from: {file_url}")
    try:
        response = requests.get(file_url, timeout=30)
        response.raise_for_status()
        repositories = [r for r in response.text.strip().split("\n") if r]
    except requests.RequestException as exc:
        logger.error(f"Failed to retrieve repository list: {exc}")
        return [], [], [], []

    accessible_repos: list[str] = []
    skipped_repos: list[str] = []
    for repo in repositories:
        logger.info(f"HEAD {repo}")
        try:
            resp = requests.head(repo, allow_redirects=True, timeout=15)
            logger.info(f"HEAD {repo} -> {resp.status_code}")
            if resp.status_code == 404:
                skipped_repos.append(repo)
            else:
                accessible_repos.append(repo)
        except requests.RequestException as exc:
            logger.warning(f"HEAD {repo} failed: {exc}")
            skipped_repos.append(repo)

    trash_dir = os.path.join(templates_dir, "TRASH")
    os.makedirs(trash_dir, exist_ok=True)

    success_repos: list[str] = []
    failed_repos: list[str] = []
    zip_fallback: list[str] = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )

    overall = progress.add_task("Processing", total=len(accessible_repos))

    with progress:
        for repo in accessible_repos:
            short_name = repo.split("/")[-1]
            repo_task = progress.add_task(short_name, total=None)
            attempt = 1
            destination = os.path.join(trash_dir, generate_destination_folder(repo, trash_dir))
            cloned = False
            while attempt <= 2 and not cloned:
                logger.info(f"Clone attempt #{attempt} {repo}")
                progress.update(repo_task, description=f"{short_name} clone #{attempt}")
                return_code, error = git_clone(repo, destination)
                if return_code == 0:
                    logger.info(f"Clone success {repo}")
                    cloned = True
                    break
                logger.warning(f"Clone failed {repo}: {error}")
                attempt += 1
                if attempt <= 2:
                    logger.info(f"Retrying {repo} in 3s")
                    time.sleep(3)

            if not cloned:
                logger.info(f"Falling back to zip for {repo}")
                progress.update(repo_task, description=f"{short_name} zip")
                zip_url = f"{repo}/archive/refs/heads/main.zip"
                alt_zip_url = f"{repo}/archive/refs/heads/master.zip"
                for url in (zip_url, alt_zip_url):
                    try:
                        with requests.get(url, stream=True, timeout=30) as r:
                            r.raise_for_status()
                            total = int(r.headers.get("Content-Length", 0))
                            zip_task = progress.add_task(
                                f"{short_name} download", total=total if total else None
                            )
                            zip_path = destination + ".zip"
                            with open(zip_path, "wb") as f:
                                for chunk in r.iter_content(chunk_size=8192):
                                    f.write(chunk)
                                    progress.advance(zip_task, len(chunk))
                            progress.remove_task(zip_task)
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

            if not cloned:
                failed_repos.append(repo)
                progress.remove_task(repo_task)
                progress.advance(overall)
                continue

            copied = 0
            for root, _, files in os.walk(destination):
                for file in files:
                    if file.endswith(".yaml"):
                        source_path = os.path.join(root, file)
                        cve_year = extract_cve_year(file)
                        if cve_year:
                            dest_folder = os.path.join(templates_dir, f"CVE-{cve_year}")
                        else:
                            dest_folder = os.path.join(templates_dir, "Vulnerability-Templates")
                        os.makedirs(dest_folder, exist_ok=True)
                        try:
                            shutil.copy2(source_path, os.path.join(dest_folder, file))
                            copied += 1
                        except OSError as exc:
                            if exc.errno == errno.ENOSPC:
                                logger.error(
                                    f"No space left on device while copying {file}. Aborting."
                                )
                            else:
                                logger.error(f"Failed to copy {file}: {exc.strerror or exc}")
                            shutil.rmtree(trash_dir, ignore_errors=True)
                            return success_repos, skipped_repos, failed_repos, zip_fallback
            logger.info(f"Copied {copied} templates from {repo}")
            success_repos.append(repo)
            shutil.rmtree(destination, ignore_errors=True)
            progress.remove_task(repo_task)
            progress.advance(overall)

    shutil.rmtree(trash_dir, ignore_errors=True)
    return success_repos, skipped_repos, failed_repos, zip_fallback


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

    success_repos, skipped_repos, failed_repos, zip_used = clone_repositories(
        args.repo_list_url, templates_dir, logger
    )
    summarize_templates(templates_dir)

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
    if success_path:
        stats_table.add_row("success list", success_path)
    console.print(stats_table)


if __name__ == "__main__":
    main()

