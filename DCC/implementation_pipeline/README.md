# Implementation Catalog

Build an implementation catalog from MITRE ATT&CK techniques in two steps:

1. Export technique content, subtechniques, and available Atomic Red Team tests to folders and per-technique JSONL files.
2. Analyze the JSONL files with an LLM to produce per-technique Excel workbooks and an optional combined catalog.

The pipeline uses `attack_techniques_export.py` and `analyze_techniques_llm.py`. Use `combine_files.py` to merge existing workbooks without running analysis.

## Requirements

- Python 3.11+ required by the pinned dependencies; local compatibility checks passed on Python 3.14.6.
- Network access to:

  - MITRE ATT&CK STIX dataset on GitHub
  - Red Canary Atomic Red Team repository for atomic tests
  - An LLM service with an OpenAI-compatible Chat Completions endpoint

From the repository directory, create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Activate the environment again when opening a new terminal. Run `deactivate` to leave it. The commands above use a POSIX shell, such as Bash or Zsh.

## Local LLM configuration

From the repository directory, copy the distribution template once:

```bash
cp .env-sample .env
chmod 600 .env
```

Edit `.env` with your service's API base URL and API key, set a model supported by that service, and set the optional CA-bundle path if required. Use the API base URL (such as `https://your-provider.example/v1`), without `/chat/completions`; the client adds that path. Do not leave the sample URL or empty API key in place. The analyzer loads this file from beside `analyze_techniques_llm.py`, even when invoked from another directory. Input, prompt, and output paths still use the current working directory, so run the pipeline from the repository directory.

| Variable | Purpose | Default |
|---|---|---|
| `LLM_BASE_URL` | API base URL, including the service's version prefix (for example, `/v1`) | Required; replace the sample URL |
| `LLM_API_KEY` | API key for that service | Required; the sample leaves it empty |
| `LLM_MODEL` | Model identifier supported by your service | `openai/gpt-oss-120b` |
| `LLM_CA_BUNDLE` | Optional PEM CA bundle; relative paths resolve from the repository directory | Empty; no custom CA bundle needed |

Values may be quoted, as shown in `.env-sample`. Variable interpolation is disabled, so API keys containing dollar signs are read literally. Keep `.env` local: Git ignores it and `.env.*` variants. Distribute `.env-sample`, which contains no credentials or internal endpoint.

The analyzer requires `.env` for every analysis run. Configuration precedence is **command-line option → `.env` → built-in default**. Shell variables do not supply or override LLM settings. There is no built-in API endpoint or API key; the model has a default, and HTTPS verification works without a custom CA bundle. `--help` works without configuration.

The API key is read only from `LLM_API_KEY` in `.env`. Missing configuration, missing keys, invalid API URLs, and unreadable or invalid PEM CA bundles produce a configuration error before any LLM request.

For TLS, the order is `--ca-bundle`, `LLM_CA_BUNDLE` in `.env`, then normal HTTPS verification without a custom CA bundle. A CLI certificate path is relative to the working directory; `LLM_CA_BUNDLE` paths are relative to the repository. Set a required organization-specific PEM bundle explicitly in `.env`. Legacy key files, certificate filename discovery, and shell TLS variables (`REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`) are not used by the analyzer.

The exporter and standalone workbook merger do not require LLM credentials.

## Step 1: Export ATT&CK Techniques (attack_techniques_export.py)

Download ATT&CK technique data and available Atomic Red Team tests, then write Markdown, JSON, and per-technique JSONL files for `analyze_techniques_llm.py`.

What it does:

- Fetches the ATT&CK Enterprise STIX bundle and indexes techniques, subtechniques, and “uses” relationships for procedure examples.
- Writes a per-technique folder under an output base (default: attack-techniques) named:
  - TXXXX - Technique-Name/
    - Description.md
    - technique.json (includes is_subtechnique, parent_stix_id, procedure_examples, and any parsed atomic_tests)
    - subtechniques.json (only for top‑level techniques)
    - atomic-red-tests.md (if available from Atomic Red Team)
    - atomic-red-tests.json (if available from Atomic Red Team)
- Generates a flattened JSONL file per requested technique ID (e.g., `T1059.jsonl`) in the current working directory. Parent-technique exports include their subtechniques; each line contains one flattened `technique.json` record.

Usage:

- Run from the repository directory.
- Single technique:
  - `python attack_techniques_export.py T1059`
- Multiple techniques:
  - `python attack_techniques_export.py T1059 T1003.001`
- By ATT&CK tactic (expands to all techniques in that tactic):
  - `python attack_techniques_export.py TA0001`
- Options:
  - `--url URL`: override the ATT&CK STIX JSON source with an HTTP(S) URL.
  - `--out PATH`: output directory for technique folders (default: `attack-techniques`); created if missing. Use the default for JSONL generation; see [known limitations](#known-limitations-and-future-work).
  - `--jsonl True|False`: write a flattened JSONL file for each TID (default: `True`). Set `False` to export technique folders without JSONL files.

Boolean options require `True` or `False`, case-insensitively (for example, `--jsonl false`). Other values are rejected. Omitting an option uses its default.

Notes:

- This step requires internet access to GitHub for ATT&CK and (optionally) Atomic Red Team content.
- For very large runs (e.g., all tactics), expect significant runtime and disk usage.

## Step 2: Analyze Techniques with an LLM (analyze_techniques_llm.py)

Send each technique's JSONL content to an LLM with the system and user prompts, then write an Excel workbook. Optionally, merge the per-technique workbooks into one catalog.

Inputs and prompts:

- The script expects a TID.jsonl in the current directory (e.g., T1059.jsonl) generated by the export step.
- Use the prompt files included in the repository:
  - `system-prompt.txt` supplies the analysis instructions and output schema.
  - `analysis-prompt.txt` supplies the user prompt. Its `<JSON HERE>` placeholder is replaced with the entire technique JSONL file.
  - Both files are read from the current working directory.
- The LLM response must be a table with nine `||`-delimited columns. The analyzer checks the header, field count, required values, ID formats, step numbers, and confidence scores from 0 to 100. Every input technique ID, including a parent technique, must appear in the output; unexpected IDs are rejected.
- A missing header or delimiter mistake may be repaired when the parser finds one unambiguous interpretation. Otherwise, malformed or incomplete output fails validation and no new workbook is written for that technique. These checks validate structure and ID coverage, not the factual accuracy of the analysis.

Complete the [local LLM configuration](#local-llm-configuration) before running the analyzer. That section covers the endpoint, API key, model, and optional CA bundle.

Usage examples:

- Run from the repository directory.
- Analyze one or more techniques after you’ve generated their JSONL files:
  - `python analyze_techniques_llm.py T1059 T1003.001`
- Analyze all techniques for which a .jsonl exists in the current directory and merge results:
  - `python analyze_techniques_llm.py ALL --combined-output True --out attack-analysis.xlsx`
- Options:
  - `techniques`: IDs such as `T1059` or `T1003.001`, or `ALL` for all local technique JSONL files. Tactic IDs are supported by the exporter only.
  - `--base-url URL`: override `LLM_BASE_URL` for this run.
  - `--model NAME`: override `LLM_MODEL` (fallback: `openai/gpt-oss-120b`).
  - `--out PATH`: combined workbook path (default: `attack-analysis.xlsx`); used with `--combined-output True`.
  - `--ca-bundle PATH`: optional PEM CA bundle path.
  - `--debug`: enable extra logging and save raw LLM text to `TID_debug_response.txt`.
  - `--write-by-technique True|False`: write `TID.xlsx` for each technique (default: `True`). `False` still runs analysis and validation but does not write per-technique workbooks.
  - `--combined-output True|False`: merge validated T-code workbooks into the file specified by `--out` (default: `False`).

Both Boolean options require `True` or `False`, case-insensitively. Other values are rejected. Combining reads existing workbooks from disk; with `--write-by-technique False --combined-output True`, it combines previously saved workbooks rather than the current responses. To combine without running analysis, use `combine_files.py` as shown below.

Outputs:

- Per technique: `TID.xlsx` in the current directory, unless `--write-by-technique False` is set.
- Optional combined workbook: if `--combined-output True`, merges all per-technique workbooks named exactly like `T1059.xlsx` or `T1003.006.xlsx` into the file set by `--out` (default: `attack-analysis.xlsx`). Other Excel files, including prior combined catalogs, are ignored. Every input workbook must have the exact catalog header and valid row values; otherwise no combined workbook is written, preventing column shifts.
- If any techniques fail, `TID_failed.txt` contains their unique IDs as a single space-separated line, ready to paste into the next run.
- Failed runs also create `error.txt` and `error_report.json`, including the validation or gateway-error reason for each failed T-code.
- The analyzer exits with status `0` on success, `1` if any technique analysis or workbook merge fails, and `2` for argument or configuration errors.

To combine existing per-technique workbooks without making LLM requests:

```bash
python combine_files.py --out attack-analysis.xlsx
```

This uses the same T-code filename filter and workbook validation as `--combined-output True`.

Troubleshooting:

- “File not found: TXXXX.jsonl … Run attack_techniques_export.py …”
  - Run the export step first, then run the analyzer from the directory containing the generated JSONL files.
- Missing Python module:
  - Activate `.venv` and run `python -m pip install -r requirements.txt` to install the project's dependencies.
- SSL/CA issues:
  - Set `LLM_CA_BUNDLE` in `.env`, or pass `--ca-bundle /path/to/ca-bundle.crt` for one run.
- LLM output not parsable:
  - Use the included prompt files and retain the `<JSON HERE>` placeholder in `analysis-prompt.txt`. The response must follow the nine-column format in `system-prompt.txt`.
- Model selection:
  - Set `LLM_MODEL` in `.env`, or pass `--model MODEL_NAME` for one run. If unset or empty, the fallback is `openai/gpt-oss-120b`.

End-to-end example:

After installing dependencies and completing the [local configuration](#local-llm-configuration), run these commands from the repository directory:

```bash
python attack_techniques_export.py T1059 T1003.001
python analyze_techniques_llm.py T1059 T1003.001 --combined-output True --out my-analysis.xlsx --debug
```

Notes:

- Re-running the exporter writes to the same technique folders and overwrites generated files with matching names. JSONL files are overwritten when JSONL output is enabled.
- The analyze step reads existing .jsonl files; you can re-run analysis without re‑exporting unless the underlying data changed.
- One previous analysis run covering 222 techniques took approximately 8–9 hours. Runtime varies with the model, service capacity, input size, and requested output; this is a historical example, not a benchmark or the current ATT&CK technique count.

## Known limitations and future work

- Make JSONL generation use the directory selected by `--out`. It currently searches the default export directory names, so use the default `attack-techniques` directory for the full export-to-analysis workflow.
- Improve handling of incomplete Atomic Red Team entries. The Markdown parser currently expects a recognizable title, description, and GUID; missing fields can cause parsing errors or reuse values from a preceding entry.
