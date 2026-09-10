#!/usr/bin/env python3
import argparse
import json
import re
import ssl
import sys
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values
from openai import OpenAI
import httpx

import pandas as pd


OUTPUT_COLUMNS = [
    "ATT&CK Technique ID",
    "ATT&CK Technique Name",
    "STIX ID",
    "Technique Implementation",
    "Implementation Step Number",
    "Implementation Step",
    "System Interaction",
    "Detection Observable",
    "Confidence Score",
]
DEFAULT_MODEL = "openai/gpt-oss-120b"


def parse_bool(value: str) -> bool:
    """Parse True or False without treating nonempty strings as true."""
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected True or False (case-insensitive)")


def row_validation_error(fields: list[str]) -> str | None:
    """Return a reason a row is unsafe to place in the fixed output schema."""
    if len(fields) != len(OUTPUT_COLUMNS):
        return f"has {len(fields)} fields; expected {len(OUTPUT_COLUMNS)}"
    if any(not field for field in fields):
        return "has empty field(s); use -- instead"
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", fields[0]):
        return "has an invalid ATT&CK Technique ID"
    if not re.fullmatch(r"(?:attack-pattern--[0-9a-f-]{36}|--)", fields[2]):
        return "has an invalid STIX ID"
    if not re.fullmatch(r"[1-9]\d*", fields[4]):
        return "has an invalid Implementation Step Number"
    try:
        confidence = float(fields[8])
    except ValueError:
        return "has a non-numeric Confidence Score"
    if not 0 <= confidence <= 100:
        return "has a Confidence Score outside 0-100"
    return None


def repair_row(fields: list[str]) -> tuple[list[str] | None, str | None]:
    """Conservatively repair only rows with one unambiguous delimiter mistake."""
    if row_validation_error(fields) is None:
        return fields, None

    candidates: list[list[str]] = []
    missing_fields = len(OUTPUT_COLUMNS) - len(fields)
    if missing_fields in (1, 2):
        for positions in combinations(range(len(OUTPUT_COLUMNS)), missing_fields):
            candidate = list(fields)
            for position in positions:
                candidate.insert(position, "--")
            if row_validation_error(candidate) is None:
                candidates.append(candidate)
    elif len(fields) == len(OUTPUT_COLUMNS) + 1:
        for position in range(len(fields) - 1):
            candidate = (
                fields[:position]
                + [f"{fields[position]} | {fields[position + 1]}"]
                + fields[position + 2:]
            )
            if row_validation_error(candidate) is None:
                candidates.append(candidate)

    unique_candidates = {tuple(candidate) for candidate in candidates}
    if len(unique_candidates) == 1:
        return list(unique_candidates.pop()), "unambiguous delimiter repair"
    return None, None


def parse_llm_table(
    response: str, expected_technique_ids: set[str] | None = None
) -> pd.DataFrame:
    """Validate and conservatively repair a fixed-width LLM table."""
    lines = [line.strip() for line in response.splitlines() if line.strip()]
    if not lines:
        raise ValueError("Empty LLM response; no workbook written.")
    if any(line.startswith("```") for line in lines):
        raise ValueError("LLM response contains a Markdown code fence; no workbook written.")

    header = [field.strip() for field in lines[0].split("||")]
    start_line = 1
    repairs: list[str] = []
    if header != OUTPUT_COLUMNS:
        repaired_first_row, repair = repair_row(header)
        if repaired_first_row is None:
            raise ValueError(
                "Invalid output header; expected exactly: " + " || ".join(OUTPUT_COLUMNS)
            )
        start_line = 0
        repairs.append("missing header inferred from the first valid data row")

    rows: list[list[str]] = []
    errors: list[str] = []
    for line_number, line in enumerate(lines[start_line:], start=start_line + 1):
        fields = [field.strip() for field in line.split("||")]
        repaired_fields, repair = repair_row(fields)
        if repaired_fields is None:
            errors.append(f"line {line_number} {row_validation_error(fields)}")
            continue
        if repair:
            repairs.append(f"line {line_number}: {repair}")
        rows.append(repaired_fields)

    if errors:
        preview = "; ".join(errors[:5])
        remaining = len(errors) - 5
        suffix = f"; plus {remaining} more error(s)" if remaining > 0 else ""
        raise ValueError(f"Malformed LLM table; no workbook written: {preview}{suffix}")
    if not rows:
        raise ValueError("LLM response contains no data rows; no workbook written.")

    if expected_technique_ids is not None:
        output_technique_ids = {row[0] for row in rows}
        missing_ids = sorted(expected_technique_ids - output_technique_ids)
        unexpected_ids = sorted(output_technique_ids - expected_technique_ids)
        coverage_errors = []
        if missing_ids:
            coverage_errors.append(f"missing input technique ID(s): {', '.join(missing_ids)}")
        if unexpected_ids:
            coverage_errors.append(f"unexpected technique ID(s): {', '.join(unexpected_ids)}")
        if coverage_errors:
            raise ValueError(
                "Incomplete technique coverage; no workbook written: "
                + "; ".join(coverage_errors)
            )

    dataframe = pd.DataFrame(rows, columns=OUTPUT_COLUMNS)
    dataframe.attrs["repairs"] = repairs
    return dataframe


def write_error_report(errors: list[dict[str, str]]) -> None:
    """Persist enough detail to rerun failed techniques after a long job."""
    if not errors:
        return
    timestamp = datetime.now(timezone.utc).isoformat()
    report = {"generated_at": timestamp, "errors": errors}
    Path("error_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    failed_tids = list(dict.fromkeys(entry["technique_id"] for entry in errors if entry.get("technique_id")))
    Path("TID_failed.txt").write_text(" ".join(failed_tids) + "\n", encoding="utf-8")
    lines = [f"Run failed at {timestamp}", "", "Failed techniques:"]
    lines.extend(f"- {entry['technique_id']}: {entry['reason']}" for entry in errors if entry.get("technique_id"))
    if failed_tids:
        lines.extend(["", "Copy-ready failed TIDs:", " ".join(failed_tids)])
    Path("error.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate_workbook_for_merge(dataframe: pd.DataFrame, source: Path) -> None:
    """Reject existing workbooks that cannot be safely combined."""
    if list(dataframe.columns) != OUTPUT_COLUMNS:
        raise ValueError(
            f"{source.name} has an invalid header; expected exactly the {len(OUTPUT_COLUMNS)} catalog columns"
        )

    errors: list[str] = []
    for row_number, row in enumerate(dataframe.itertuples(index=False, name=None), start=2):
        fields = ["" if pd.isna(value) else str(value).strip() for value in row]
        if len(fields) != len(OUTPUT_COLUMNS) or any(not field for field in fields):
            errors.append(f"row {row_number} has missing field(s)")
            continue
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", fields[0]):
            errors.append(f"row {row_number} has an invalid ATT&CK Technique ID")
            continue
        if not re.fullmatch(r"(?:attack-pattern--[0-9a-f-]{36}|--)", fields[2]):
            errors.append(f"row {row_number} has an invalid STIX ID")
            continue
        try:
            step_number = float(fields[4])
            confidence = float(fields[8])
        except ValueError:
            errors.append(f"row {row_number} has a non-numeric step number or confidence score")
            continue
        if not step_number.is_integer() or step_number < 1:
            errors.append(f"row {row_number} has an invalid Implementation Step Number")
            continue
        if not 0 <= confidence <= 100:
            errors.append(f"row {row_number} has a Confidence Score outside 0-100")
            continue

    if errors:
        preview = "; ".join(errors[:5])
        remaining = len(errors) - 5
        suffix = f"; plus {remaining} more error(s)" if remaining > 0 else ""
        raise ValueError(f"{source.name} is malformed: {preview}{suffix}")

def construct_user_content(user_template: str, tid: str):
    """Insert the technique JSONL into the user prompt template."""
    content = user_template
    has_desc_ph = "<JSON HERE>" in content
    if has_desc_ph:
        base_dir = Path.cwd()
        path = base_dir / f"{tid}.jsonl"
        jsonlines = ""
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}. Run attack_techniques_export.py with the corresponding T-code first")
        with path.open("r", encoding="utf-8") as f:
            jsonlines = f.read()
            content = content.replace("<JSON HERE>", jsonlines or "")
    return content


def input_technique_ids(tid: str) -> set[str]:
    """Read the exact technique IDs that the LLM must represent in its output."""
    path = Path(f"{tid}.jsonl")
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}. Run attack_techniques_export.py first")
    technique_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            technique_id = str(json.loads(line)["technique_id"]).strip().upper()
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"Invalid JSONL record at {path}:{line_number}: {exc}") from exc
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique_id):
            raise ValueError(f"Invalid technique ID at {path}:{line_number}: {technique_id}")
        technique_ids.add(technique_id)
    if not technique_ids:
        raise ValueError(f"No technique IDs found in {path}")
    return technique_ids

def call_llm(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    verify: ssl.SSLContext | bool,
    base_url: str,
    ) -> str:
    
    # Use the resolved CA bundle for every LLM request. A separate connection
    # timeout fails unavailable endpoints quickly, while the 10-minute default
    # allows the model sufficient time to generate a full catalog response.
    timeout = httpx.Timeout(600.0, connect=30.0)
    with httpx.Client(verify=verify, timeout=timeout, trust_env=False) as http_client:
        client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            http_client=http_client,
        )
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
    if not resp.choices or not resp.choices[0].message or not resp.choices[0].message.content:
        raise RuntimeError("No choices returned from LLM")
    response = resp.choices[0].message.content.strip()
    print(response)
    return response

def merge_excel(out: str):
    """Merge only per-technique workbooks, excluding lock files and this output."""
    current_directory = Path(".")
    output_path = Path(out).resolve()
    all_files = sorted(
        file
        for file in current_directory.glob("*.xlsx")
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?\.xlsx", file.name)
        and not file.name.startswith("~$")
        and file.resolve() != output_path
    )
    if not all_files:
        raise ValueError("No per-technique T-code workbooks available to merge.")
    
    df_list = []
    invalid_workbooks: list[str] = []
    for file in all_files:
        try:
            df = pd.read_excel(file)
            validate_workbook_for_merge(df, file)
        except (ValueError, OSError) as exc:
            invalid_workbooks.append(str(exc))
            continue
        df_list.append(df)
    if invalid_workbooks:
        preview = "; ".join(invalid_workbooks[:5])
        remaining = len(invalid_workbooks) - 5
        suffix = f"; plus {remaining} more invalid workbook(s)" if remaining > 0 else ""
        raise ValueError(
            f"Combined workbook not written because {len(invalid_workbooks)} input workbook(s) failed validation: "
            f"{preview}{suffix}"
        )
    combined_results = pd.concat(df_list, ignore_index=True)
    combined_results.to_excel(out, index=False)
    print(f"Wrote {out}")
    
def main():
    project_dir = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Analyze ATT&CK techniques using LLM and output to Excel.")
    ap.add_argument("techniques", nargs="+", help="ATT&CK technique IDs (e.g., T1059 T1003.001) or ALL for all jsonl files to be used as Technique IDs")
    ap.add_argument("--base-url", default=None, help="Override LLM_BASE_URL from the required .env file")
    ap.add_argument(
        "--model",
        default=None,
        help=f"LLM model name (default: LLM_MODEL in .env, then {DEFAULT_MODEL})",
    )
    ap.add_argument("--out", default="attack-analysis.xlsx", help="Output Excel file path")
    ap.add_argument("--ca-bundle", default=None, help="Override LLM_CA_BUNDLE from .env with a PEM CA bundle path")
    ap.add_argument("--debug", action="store_true", help="Enable debug logging to stderr")
    ap.add_argument("--write-by-technique", type=parse_bool, default=True, metavar="{True,False}", help="Write a workbook for each technique (case-insensitive; default: True)")
    ap.add_argument("--combined-output", type=parse_bool, default=False, metavar="{True,False}", help="Merge existing per-technique workbooks (case-insensitive; default: False)")

    args = ap.parse_args()

    try:
        with (project_dir / ".env").open(encoding="utf-8") as env_file:
            config = dotenv_values(stream=env_file, interpolate=False)
    except FileNotFoundError:
        ap.error("Missing .env beside analyze_techniques_llm.py; copy .env-sample to .env and configure your service")
    except (OSError, UnicodeError):
        ap.error("Cannot read .env; check its permissions and UTF-8 encoding")

    if args.base_url is None:
        args.base_url = config.get("LLM_BASE_URL") or ""
    if args.model is None:
        args.model = (config.get("LLM_MODEL") or "").strip() or DEFAULT_MODEL
    args.base_url = args.base_url.strip()
    try:
        parsed_url = urlsplit(args.base_url)
        valid_url = (
            parsed_url.scheme in ("http", "https")
            and bool(parsed_url.hostname)
            and not any(char.isspace() for char in args.base_url)
            and parsed_url.username is None
            and parsed_url.password is None
            and not parsed_url.query
            and not parsed_url.fragment
        )
        parsed_url.port  # Validate an explicitly supplied port.
    except ValueError:
        valid_url = False
    if not valid_url:
        ap.error("Set LLM_BASE_URL in .env or pass --base-url with an HTTP(S) API base URL")
    args.model = args.model.strip()
    if not args.model:
        ap.error("--model must be a nonempty model identifier")
    
    # Start script timer for debugging
    if args.debug:
        import time
        start_time = time.perf_counter()
        
    # If ALL is requested, use every technique JSONL file in the current directory.
    if any(t.upper() == "ALL" for t in args.techniques):
        tids = [
            f.stem.upper()
            for f in Path(".").glob("*.jsonl")
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", f.stem.upper())
        ]
    else:
        tids = [t.strip().upper() for t in args.techniques]
        
    api_key = (config.get("LLM_API_KEY") or "").strip()
    if not api_key:
        ap.error("Set LLM_API_KEY in .env")

    # Resolve the CA bundle for TLS verification.
    if args.debug:
        print(f"[Debug] Techniques: {', '.join(tids)}", file=sys.stderr)
    llm_ca = (config.get("LLM_CA_BUNDLE") or "").strip()
    ca_path = args.ca_bundle if args.ca_bundle is not None else llm_ca
    verify: ssl.SSLContext | bool = True
    if ca_path:
        bundle_path = Path(ca_path).expanduser()
        if not args.ca_bundle and llm_ca and not bundle_path.is_absolute():
            bundle_path = project_dir / bundle_path
        if not bundle_path.is_file():
            ap.error("Configured CA bundle does not exist or is not a file")
        try:
            verify = ssl.create_default_context(cafile=str(bundle_path))
        except (OSError, ValueError):
            ap.error("Cannot load CA bundle; provide a readable PEM certificate bundle")
    if args.debug:
        v_desc = str(bundle_path) if ca_path else "default HTTPS verification"
        print(f"[Debug] Using CA verify: {v_desc}", file=sys.stderr)

    # Load the user prompt.
    default_user_prompt = "Analyze the following techniques:"
    user_path = Path("analysis-prompt.txt")
    if user_path.exists():
        usertxt = user_path.read_text(encoding="utf-8", errors="ignore").strip()
        user_prompt_template = usertxt if usertxt else default_user_prompt
    else:
        user_prompt_template = default_user_prompt
    if args.debug:
        usrc = str(user_path) if user_path.exists() else "<default>"
        print(f"[Debug] Loaded user prompt from: {usrc}", file=sys.stderr)
    
    # Load the system prompt.
    default_system_prompt = "You are a helpful cybersecurity assistant."
    spath = Path("system-prompt.txt")
    if spath.exists():
        sptxt = spath.read_text(encoding="utf-8", errors="ignore").strip()
        system_prompt = sptxt if sptxt else default_system_prompt
    else:
        system_prompt = default_system_prompt
    if args.debug:
        ssrc = str(spath) if spath.exists() else "<default>"
        print(f"[Debug] Loaded system prompt from: {ssrc}", file=sys.stderr)

    # Write one Excel workbook per requested technique (including its subtechniques)
    error_records: list[dict[str, str]] = []
    
    for tid in tids:
        try:
            if args.debug:
                print(f"[Debug] Requesting analysis for {tid}", file=sys.stderr)
            user_prompt = construct_user_content(user_prompt_template, tid)
            expected_technique_ids = input_technique_ids(tid)
            response = call_llm(api_key, args.model, system_prompt, user_prompt, verify, args.base_url)
            if args.debug:
                print("LLM Response Received")
                with open(f"{tid}_debug_response.txt", "w") as f:
                    f.write(response)
            df = parse_llm_table(response, expected_technique_ids)
            for repair in df.attrs.get("repairs", []):
                print(f"[Repair] tid={tid}: {repair}", file=sys.stderr)
            
            if args.write_by_technique:
                # Output filename is the technique ID (e.g., T1053.xlsx)
                out_path = Path(f"{tid}.xlsx")
                df.to_excel(out_path, index=False)
                print(f"Wrote {out_path}")
            
        except Exception as e:
            print(f"[Error] tid={tid}: {e}")
            error_records.append(
                {
                    "technique_id": tid,
                    "reason": str(e),
                }
            )
            continue
        
    
    # Write the combined results to Excel
    if args.combined_output:
        try:
            merge_excel(args.out)
        except Exception as e:
            print(f"[Error] combined workbook: {e}", file=sys.stderr)
            error_records.append({"technique_id": "", "reason": f"combined workbook: {e}"})
    
    if error_records:
        write_error_report(error_records)
        print(f"Wrote TID_failed.txt, error.txt, and error_report.json with {len(error_records)} error(s)")
        
    # End script timer
    if args.debug:
        end_time = time.perf_counter()
        print(f"Runtime: {end_time - start_time:.4f} seconds")
    return 1 if error_records else 0

if __name__ == "__main__":
    sys.exit(main())
