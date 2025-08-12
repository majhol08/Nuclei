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

4.  Sit back and relax! The script will start collecting the Nuclei templates
    from public repositories and present rich progress bars and a live log. A
    `run.log` file is saved into the output directory capturing every step with
    timestamps. Unreachable repositories are skipped before cloning and the
    final report shows counts of successful, skipped, failed and ZIP-fallback
    clones along with the log path (and success list if requested).
 <img src="https://i.ibb.co/hCh6vXB/image.png" width=500/>

> **Note:** ensure that you have sufficient free disk space before running the
> collector. The script will now stop gracefully if the disk fills up while
> copying templates.

## Result :file_folder:

Once the script completes, it will display the total count of templates in a tabular format. It will create a folder named `Templates`  in the repository's root directory. Inside this folder, you'll find subfolders for each cloned repository segregated as per publication year `CVE-20XX` and others as `Vulnerability-Templates`. Each template is stored as a separate file, enabling easy access and utilization for your bug bounty or security testing activities.

## Disclaimer :exclamation:

Please ensure that you comply with all relevant laws, terms of service, and guidelines when using this tool. The Nuclei tool and the collected templates should be used responsibly and ethically. The creators of this script are not responsible for any misuse or illegal activities performed using the gathered templates.

## Contributions :raising_hand:

Contributions to this project are welcome! If you have any updated and new github repo for nuclei templates, feel free to submit a pull request for `PleaseUpdateMe.txt`

## License :page_facing_up:

This project is licensed under the [MIT License](https://github.com/AggressiveUser/AllForOne/blob/main/LICENSE).
