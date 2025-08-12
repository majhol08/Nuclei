# MX8_TMPLT – Nuclei Template Collector

MX8_TMPLT is a command-line utility that gathers [Nuclei](https://github.com/projectdiscovery/nuclei) templates from many public repositories into a single organized folder. It is developed by **mon3im.officeil** and is aimed at security researchers and bug bounty hunters who want the latest templates in one run.

## Features
- Automatically finds the largest writable partition and uses it for cache, store, and temporary files.
- Downloads templates using `git`, the GitHub API, or ZIP archives when needed.
- Deduplicates files by SHA-1 hash inside a `.store/` directory and hard-links them into an organized tree.
- Resumes safely after interruptions and writes a detailed `run.log` for each run.
- Stops gracefully on low disk space or when Ctrl+C is pressed.
- Rich terminal interface shows per-repository status and live counters.

## Requirements
- Python 3.10 or newer.
- Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage
1. Clone the project:

```bash
git clone https://github.com/mon3imofficeil/MX8_TMPLT.git
cd MX8_TMPLT
```

2. Run with sensible defaults:

```bash
python MX8_TMPLT.py
```

3. Display help:

```bash
python MX8_TMPLT.py -h
```

### Options
- `--repo-list-url <url>` – URL to a text file containing repository URLs (one per line).
- `--output-dir <dir>` – Directory where templates and metadata will be stored (default: `Templates`).
- `--temp-dir <dir>` – Directory for cache, store, and temporary files (overrides automatic mount selection).
- `--save-success-list <file>` – Write successfully cloned repository URLs to a text file.
- `--save-templates <archive.zip>` – Create a zip archive of all collected templates.
- `--setup` – Launch the interactive setup wizard again.
- `--reset-config` – Ignore the saved configuration for this run.
- `--yes` – Assume defaults and run non-interactively.

## Output
After a run you will find:

- `.store/` – Unique YAML blobs named by SHA-1.
- `Templates/` – Primary view: `CVE/<year>/CVE-*.yaml` or `<protocol>/<severity>/<vendor>/<product>/<slug>.yaml`.
- `Indexes/` – Secondary hard-link indexes grouped by severity, type, vendor/product, and tags.
- `manifest.json` – Status of each repository (updated, skipped, failed, etc.).
- `content-index.json` – Metadata for each unique SHA-1.
- `run.log` – Detailed log with timestamps for troubleshooting.

## Notes
- Ensure enough disk space; the tool checks free space and stops gracefully when low.
- Re-running the tool skips repositories that were processed successfully.

## License
This project is licensed under the [MIT](LICENSE) license.
