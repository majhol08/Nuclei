# AllForOne - Nuclei Template Collector 👤
<img width=350px src="https://i.ibb.co/SKGmMyM/WEEEK-1.png" alt="AllForOne - Nuclei Template Collector">

Welcome to the "AllForOne" repository! :rocket: This repository contains a Python script that allows bug bounty hunters and security researchers to collect all Nuclei YAML templates from various public repositories, helping to streamline the process of downloading multiple templates using just a single repository.

## How it Works :gear:

The script leverages the GitHub repositories which containing Nuclei Templates. It will clones them to your local machine, and extracts the templates, organizing them for easy access.

## 👋 Connect with me

[![LinkedIn](https://img.shields.io/badge/-LinkedIn-blue?style=flat-square&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/AggressiveUser/)](https://www.linkedin.com/in/AggressiveUser/) [![Hack The Box](https://img.shields.io/badge/-Hack%20The%20Box-green?style=flat-square&logo=hack-the-box&logoColor=white&link=https://app.hackthebox.com/profile/17569)](https://app.hackthebox.com/profile/17569) [![GitHub](https://img.shields.io/badge/-GitHub-black?style=flat-square&logo=github&link=https://github.com/AggressiveUser)](https://github.com/AggressiveUser) [![Twitter](https://img.shields.io/badge/-Twitter-blue?style=flat-square&logo=twitter&logoColor=white&link=https://twitter.com/AggressiveUserX)](https://twitter.com/AggressiveUserX) [![Telegram](https://img.shields.io/badge/-Telegram-blue?style=flat-square&logo=telegram&logoColor=white&link=https://t.me/AggressiveUser)](https://t.me/AggressiveUser) [![Email](https://img.shields.io/badge/-Email-red?style=flat-square&logo=Microsoft&logoColor=white&link=mailto:AggressiveUser@OutLook.com)](mailto:AggressiveUser@OutLook.com)

## Getting Started :rocket:

To get started, follow these steps:

1.  Clone the repository:
```git clone https://github.com/AggressiveUser/AllForOne.git```  :computer:

2.  Install the required dependencies:
```pip install -r requirements.txt```  :key:

3.  Run the script (use `-h` to see available options):

```bash
python AllForOne.py --repo-list-url <url> --output-dir <directory>
```

   - `--repo-list-url` *(optional)* URL pointing to a text file containing
     repository links. Defaults to
     `https://raw.githubusercontent.com/AggressiveUser/AllForOne/main/PleaseUpdateMe.txt`
   - `--output-dir` *(optional)* directory where the collected templates will be
     stored. Defaults to `Templates`
   - `--save-success-list` *(optional)* path to save successfully cloned
    repositories for later reuse

4.  Sit back and watch an animated dashboard. A single interactive screen keeps
    at most a handful of lines, one per active repository. Each phase uses a
    different spinner and emoji (🔍 HEAD, ⬇️ clone, ♻️ retry, 📦 zip, 📂 extract,
    📄 copy) while a sticky summary bar tracks totals and ETA. Waiting/backoff
    shows a large countdown, and completion ends with a brief confetti splash.
    A `run.log` captures every step with timestamps while the console remains
    clean. Repositories already cloned live in `Templates/.cache/repos` and are
    updated with `git pull` on subsequent runs, so only new or changed YAML
    files are copied. Unreachable repositories are skipped before cloning and
    the final report shows counts of updated, up-to-date, skipped and failed
    repositories along with the log path, manifest and optional success list.
<img src="https://i.ibb.co/hCh6vXB/image.png" width=500/>

> **Note:** ensure that you have sufficient free disk space before running the
> collector. The script will now stop gracefully if the disk fills up while
> copying templates.

Each copy uses SHA‑1 deduplication: identical YAML files are written once and
tracked in `content-index.json`. The `manifest.json` remembers the last commit
or check time for every repository so reruns avoid reprocessing unchanged
sources. A shared `.store` directory keeps a single copy of each unique
template addressed by its hash; project folders receive hard links pointing to
that content. During updates the collector compares SHA‑1 hashes and replaces
changed files atomically while skipping duplicates. After each run orphaned
blobs are removed from `.store` and the count is reported. The accompanying
`url-registry.json` lists every raw YAML URL fetched along with its size and
hash for auditing. Repositories returning 404 are noted under
`deprecated_repos` in `manifest.json` and skipped on subsequent runs.

Press `Ctrl+C` to cancel at any time. The collector will finish the file in
progress, clean temporary data, write a summary to `run.log` and
`manifest.json`, then exit without a traceback. On the next run it reads
`manifest.json` and automatically skips repositories that were already cloned
successfully so you can resume where you left off.

## Result :file_folder:

Once the script completes, it will display the total count of templates in a tabular format. It will create a folder named `Templates`  in the repository's root directory. Inside this folder, you'll find subfolders for each cloned repository segregated as per publication year `CVE-20XX` and others as `Vulnerability-Templates`. Each template is stored as a separate file, enabling easy access and utilization for your bug bounty or security testing activities.

## Disclaimer :exclamation:

Please ensure that you comply with all relevant laws, terms of service, and guidelines when using this tool. The Nuclei tool and the collected templates should be used responsibly and ethically. The creators of this script are not responsible for any misuse or illegal activities performed using the gathered templates.

## Contributions :raising_hand:

Contributions to this project are welcome! If you have any updated and new github repo for nuclei templates, feel free to submit a pull request for `PleaseUpdateMe.txt`

## License :page_facing_up:

This project is licensed under the [MIT License](https://github.com/AggressiveUser/AllForOne/blob/main/LICENSE).
