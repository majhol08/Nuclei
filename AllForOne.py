"""Nuclei template collector.

This script fetches a list of template repositories, clones them concurrently
and organises the templates by CVE year.  A small command line interface built
with ``argparse`` and ``rich`` provides a colourful and user friendly
experience.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import time
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table


console = Console()


def git_clone(url: str, destination: str) -> tuple[int, str]:
    """Clone a git repository to ``destination`` and return result code and
    stderr."""

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", "clone", url, destination],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=env,
    )
    return result.returncode, result.stderr.decode().strip()


def generate_destination_folder(url: str, trash_dir: str) -> str:
    """Generate a unique folder name for the repository under ``trash_dir``."""

    folder_name = os.path.basename(url.rstrip(".git"))
    counter = 1
    while os.path.exists(os.path.join(trash_dir, folder_name)):
        folder_name = f"{os.path.basename(url.rstrip('.git'))}_{counter}"
        counter += 1
    return folder_name


def clone_repository(repo: str, trash_dir: str) -> str | None:
    """Clone a single repository and return the repo URL on failure."""

    destination = generate_destination_folder(repo, trash_dir)
    return_code, error_msg = git_clone(repo, os.path.join(trash_dir, destination))
    if return_code != 0 or "Username for" in error_msg:
        return repo
    return None


def clone_repositories(
    file_url: str,
    templates_dir: str,
    max_workers: int = 6,
) -> tuple[list[str], list[str], list[str]]:
    """Clone all repositories listed at ``file_url`` into ``templates_dir``.

    Returns lists of successful, skipped and failed repository URLs."""

    console.print(f"[bold]Fetching repository list from:[/] {file_url}")
    try:
        response = requests.get(file_url, timeout=30)
        response.raise_for_status()
        repositories = [r for r in response.text.strip().split("\n") if r]
    except requests.RequestException as exc:  # pragma: no cover - network failure
        console.print(f"[red]Failed to retrieve repository list: {exc}[/]")
        return [], [], []

    accessible_repos: list[str] = []
    skipped_repos: list[str] = []
    for repo in repositories:
        try:
            resp = requests.head(repo, allow_redirects=True, timeout=15)
            if resp.status_code == 404:
                skipped_repos.append(repo)
            else:
                accessible_repos.append(repo)
        except requests.RequestException:
            skipped_repos.append(repo)

    if skipped_repos:
        console.print(f"[yellow]Skipping {len(skipped_repos)} unavailable repositories[/]")

    trash_dir = os.path.join(templates_dir, "TRASH")
    os.makedirs(trash_dir, exist_ok=True)

    success_repos: list[str] = []
    failed_repos: list[str] = []

    progress_columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} repos"),
    ]

    with Progress(*progress_columns, console=console) as progress:
        task = progress.add_task("Cloning", total=len(accessible_repos))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(clone_repository, repo, trash_dir): repo
                for repo in accessible_repos
            }
            for future in as_completed(futures):
                repo = futures[future]
                failed_repo = future.result()
                if failed_repo:
                    failed_repos.append(repo)
                else:
                    success_repos.append(repo)
                progress.update(task, advance=1)

    if failed_repos:
        console.print("[red]Failed to clone the following repositories:[/]")
        for repo in failed_repos:
            console.print(f"  - {repo}")

    # Copy templates into final structure
    for root, _, files in os.walk(trash_dir):
        for file in files:
            if file.endswith(".yaml"):
                source_path = os.path.join(root, file)
                cve_year = extract_cve_year(file)
                if cve_year:
                    destination_folder = os.path.join(templates_dir, f"CVE-{cve_year}")
                else:
                    destination_folder = os.path.join(templates_dir, "Vulnerability-Templates")
                os.makedirs(destination_folder, exist_ok=True)
                try:
                    shutil.copy2(source_path, os.path.join(destination_folder, file))
                except OSError as exc:
                    if exc.errno == errno.ENOSPC:
                        console.print(
                            f"[red]No space left on device while copying {file}. Aborting.[/]"
                        )
                    else:
                        console.print(
                            f"[red]Failed to copy {file}: {exc.strerror or exc}[/]"
                        )
                    shutil.rmtree(trash_dir, ignore_errors=True)
                    return success_repos, skipped_repos, failed_repos

    console.print("\n[green]Removing caches and temporary files[/]")
    shutil.rmtree(trash_dir, ignore_errors=True)
    time.sleep(1)

    return success_repos, skipped_repos, failed_repos


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
    """Print a summary table of collected templates."""

    cve_folders = glob.glob(os.path.join(templates_dir, "CVE-*"))
    cve_yaml_count = sum(count_yaml_files(folder) for folder in cve_folders)

    vulnerability_templates_folder = os.path.join(templates_dir, "Vulnerability-Templates")
    vulnerability_yaml_count = count_yaml_files(vulnerability_templates_folder)

    total_yaml_count = cve_yaml_count + vulnerability_yaml_count

    table = Table(title="Template Summary")
    table.add_column("Template Type")
    table.add_column("Count", justify="right")
    table.add_row("CVE Templates", str(cve_yaml_count))
    table.add_row("Other Vulnerability Templates", str(vulnerability_yaml_count))
    table.add_row("Total Templates", str(total_yaml_count))

    console.print(table)


def banner() -> None:
    console.print("[bold magenta]Nuclei Template Collector[/]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Nuclei templates from public repositories.")
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

    success_repos, skipped_repos, failed_repos = clone_repositories(
        args.repo_list_url, templates_dir
    )
    summarize_templates(templates_dir)

    if args.save_success_list:
        success_path = os.path.abspath(args.save_success_list)
        with open(success_path, "w", encoding="utf-8") as f:
            f.write("\n".join(success_repos))
        console.print(f"[green]Successful repositories saved to [bold]{success_path}[/]")

    console.print("\n[bold]Repository statistics[/]")
    stats_table = Table(show_header=False)
    stats_table.add_row("Successful", str(len(success_repos)))
    stats_table.add_row("Skipped", str(len(skipped_repos)))
    stats_table.add_row("Failed", str(len(failed_repos)))
    console.print(stats_table)


if __name__ == "__main__":
    main()

