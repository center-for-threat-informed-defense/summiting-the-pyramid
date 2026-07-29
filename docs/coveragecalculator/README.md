# Coverage Calculator

Coverage Calculator analyzes one or more [Sigma](https://sigmahq.io/) detection rules and produces an Excel workbook that connects those analytics to ATT&CK technique implementations. It also scores analytic fields for robustness and precision, and adds OCSF event/field context where available.

## Requirements

- Python 3.10 or newer
- The included reference workbooks:
  - `scoring_dictionary.xlsx`
  - `implementation_catalog_with_attack_components.xlsx`
  - `mappings.xlsx`

Install the Python dependencies:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Usage

Run the script from this directory and give it a Sigma YAML file, a directory of YAML files, a glob, or a GitHub URL.

```sh
python3 sigma_analytic_tables.py path/to/rule.yml
```

For example, process the SigmaHQ Windows process-access rules directly from GitHub:

```sh
python3 sigma_analytic_tables.py \
  "https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_access"
```

Multiple inputs may be supplied either positionally or with `--analytic-yaml`:

```sh
python3 sigma_analytic_tables.py rules/windows/*.yml --analytic-yaml rules/custom_rule.yml
```

The default output is `outputs/consolidated_analysis.xlsx`. Set a different output prefix with `--out-prefix`:

```sh
python3 sigma_analytic_tables.py rules/ --out-prefix outputs/windows_coverage
```

This writes `outputs/windows_coverage.xlsx`.

## Output workbook

The generated workbook contains these worksheets:

- `Summary` — source information and aggregate results.
- `Implementations` — ATT&CK implementation coverage and matching analytics.
- `Technique Coverage` — per-technique implementation coverage.
- `Analytic Scores` — robustness and precision scores for each analytic.
- `Field Scores` — field-level scoring and match details.
- `OCSF Context` — matching log-source, Event ID, data-component, and OCSF context.

## Reference data and options

By default, the script reads the three reference workbooks stored beside it. You can provide updated versions or select worksheet names when needed:

```sh
python3 sigma_analytic_tables.py rule.yml \
  --scoring-workbook data/scoring_dictionary.xlsx \
  --scoring-sheet "New Scores" \
  --implementation-catalog data/implementation_catalog.xlsx \
  --attack-sheet "Implementations" \
  --ocsf-mapping-workbook data/mappings.xlsx \
  --event-field-sheet "OCSF Mappings"
```

`--event-field-data` accepts either an Excel workbook or CSV file. The OCSF mapping input can be omitted by passing no mapping file only when adapting the script; the supplied mapping workbook is used by default.

For private GitHub repositories or to avoid unauthenticated GitHub API limits, set `GITHUB_TOKEN` before running the script:

```sh
export GITHUB_TOKEN=your_token
python3 sigma_analytic_tables.py "https://github.com/OWNER/REPOSITORY/tree/BRANCH/path"
```

Run `python3 sigma_analytic_tables.py --help` for the complete list of options.

## Troubleshooting

- **Missing dependency:** rerun `python3 -m pip install -r requirements.txt` in the active virtual environment.
- **No Sigma files found:** verify that the path, glob, or GitHub tree URL points to YAML rule files.
- **Missing worksheet or columns:** use the corresponding `--*-sheet` option, or verify that the replacement reference file has the expected schema.
