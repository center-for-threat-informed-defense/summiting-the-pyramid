#!/usr/bin/env python3
import argparse
import os
import re
import sys
import json
import requests
from pathlib import Path
from langchain_text_splitters import MarkdownHeaderTextSplitter
from typing import Dict, List, Optional, Tuple, Iterable, Any


ATTACK_JSON_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/"
    "master/enterprise-attack/enterprise-attack.json"
)

ATOMIC_RED_URL_TMPL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/"
    "master/atomics/{tid}/{tid}.md"
)

def parse_bool(value: str) -> bool:
    """Parse True or False without treating nonempty strings as true."""
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected True or False (case-insensitive)")


def slugify(text: str, max_len: int = 80) -> str:
    text = text.strip()
    text = re.sub(r"[\s\/\\]+", " ", text)
    text = re.sub(r"[\:\*\?\"\<\>\|]", "", text)
    text = text.replace("..", ".")
    text = text.strip()
    text = re.sub(r"\s+", "-", text)
    if len(text) > max_len:
        text = text[:max_len].rstrip("-_")
    return text or "untitled"

def load_attack_json(url: str) -> dict:
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    return r.json()

def get_external_id(obj: dict) -> Optional[str]:
    refs = obj.get("external_references", [])
    for ref in refs:
        ext_id = ref.get("external_id")
        if ext_id and ext_id.startswith("T"):
            return ext_id
    return None

def build_indexes(bundle: dict):
    objects = bundle.get("objects", [])
    by_id: Dict[str, dict] = {}
    attack_patterns: Dict[str, dict] = {}
    subtechniques_by_parent: Dict[str, List[dict]] = {}
    uses_by_target: Dict[str, List[dict]] = {}
    tactic_map: Dict[str, str] = {}
    
    for obj in objects:
        obj_id = obj.get("id")
        if obj_id:
            by_id[obj_id] = obj

    for obj in objects:
        if obj.get("type") == "attack-pattern":
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ext_id = get_external_id(obj)
            if ext_id:
                attack_patterns[ext_id] = obj
            if obj.get("x_mitre_is_subtechnique"):
                parent_ref = obj.get("x_mitre_parent_attack_pattern_ref")
                if parent_ref:
                    subtechniques_by_parent.setdefault(parent_ref, []).append(obj)
        if obj.get("type") == "x-mitre-tactic":
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tid = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                None,
            )
            
            shortname = obj.get("x_mitre_shortname")
            if tid and shortname:
                tactic_map[tid] = shortname
            
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
            target_ref = obj.get("target_ref")
            if target_ref and target_ref in by_id:
                uses_by_target.setdefault(target_ref, []).append(obj)

    return by_id, attack_patterns, subtechniques_by_parent, uses_by_target, tactic_map

def extract_technique_json(
    tech: dict,
    by_id: Dict[str, dict],
    uses_by_target: Dict[str, List[dict]],
    subtechniques: Optional[List[Tuple[str, str]]] = None,
):
    name = tech.get("name", "")
    tech_id = get_external_id(tech) or ""
    description = (tech.get("description", "") or "").strip()
    stix_id = tech.get("id")
    is_sub = bool(tech.get("x_mitre_is_subtechnique"))
    parent_stix_id = tech.get("x_mitre_parent_attack_pattern_ref") if is_sub else None

    # Build procedure examples following extract_technique_markdown's flow
    rels = uses_by_target.get(stix_id or "", [])
    procedures: List[dict] = []
    for rel in rels:
        src_id = rel.get("source_ref")
        if not isinstance(src_id, str):
            # Skip relationships with malformed source refs
            continue
        src_obj = by_id.get(src_id, {})
        src_name = src_obj.get("name") or src_id
        src_type = src_obj.get("type", "object")
        src_ext = None
        for ref in (src_obj.get("external_references") or []):
            if ref.get("external_id"):
                src_ext = ref.get("external_id")
                break
        rel_desc = rel.get("description") or ""
        label = f"{src_name} ({src_ext})" if src_ext else f"{src_name} ({src_type})"
        procedures.append({
            "label": label,
            "external_id": src_ext,
            "description": rel_desc,
        })

    procedures = sorted(procedures, key=lambda x: x.get("label", ""))

    # Include subtechniques info only for top-level techniques if provided
    subs_json: Optional[List[dict]] = None
    if subtechniques and not is_sub:
        subs_json = [{"id": st_id, "name": st_name} for st_id, st_name in subtechniques]

    data = {
        "technique_id": tech_id,
        "stix_id": stix_id,
        "name": name,
        "description": description,
        "is_subtechnique": is_sub,
        "parent_stix_id": parent_stix_id,
        "procedure_examples": procedures,
    }
    if subs_json is not None:
        data["subtechniques"] = subs_json
    return data
    


def extract_technique_markdown(
    tech: dict,
    by_id: Dict[str, dict],
    uses_by_target: Dict[str, List[dict]],
    subtechniques: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[str, List[Tuple[str, Optional[str], str]]]:
    name = tech.get("name", "")
    tech_id = get_external_id(tech) or ""
    description = tech.get("description", "").strip()
    md_lines: List[str] = []
    md_lines.append(f"# {tech_id} - {name}")
    md_lines.append("")
    if description:
        md_lines.append("## Description")
        md_lines.append("")
        md_lines.append(description)
        md_lines.append("")

    # Include subtechniques only for top-level techniques if provided
    if subtechniques and not tech.get("x_mitre_is_subtechnique"):
        md_lines.append("## Subtechniques")
        md_lines.append("")
        if subtechniques:
            for st_id, st_name in subtechniques:
                md_lines.append(f"- {st_id} - {st_name}")
        else:
            md_lines.append("- None")
        md_lines.append("")

    rels = uses_by_target.get(tech.get("id") or "", [])
    procedures: List[Tuple[str, Optional[str], str]] = []
    for rel in rels:
        src_id = rel.get("source_ref")
        if not isinstance(src_id, str):
            # Skip relationships with malformed source refs
            continue
        src_obj = by_id.get(src_id, {})
        src_name = src_obj.get("name") or src_id
        src_type = src_obj.get("type", "object")
        src_ext = None
        for ref in src_obj.get("external_references", []) or []:
            if ref.get("external_id"):
                src_ext = ref.get("external_id")
                break
        rel_desc = rel.get("description") or ""
        src_label = src_name
        if src_ext:
            src_label = f"{src_name} ({src_ext})"
        else:
            src_label = f"{src_name} ({src_type})"
        procedures.append((src_label, src_ext, rel_desc))

    if procedures:
        md_lines.append("## Procedure Examples")
        md_lines.append("")
        for label, _ext, rel_desc in sorted(procedures, key=lambda x: x[0]):
            if rel_desc:
                md_lines.append(f"- {label}: {rel_desc}")
            else:
                md_lines.append(f"- {label}")
        md_lines.append("")
    else:
        md_lines.append("## Procedure Examples")
        md_lines.append("")
        md_lines.append("- None found in relationships")
        md_lines.append("")

    return "\n".join(md_lines), procedures

def ensure_dir_for_tech(tech: dict, base_dir: Path) -> Path:
    tech_id = get_external_id(tech) or tech.get("id")
    name = tech.get("name", "")
    dir_name = f"{tech_id} - {slugify(name)}"
    path = base_dir / dir_name
    path.mkdir(parents=True, exist_ok=True)
    return path

def write_markdown(out_dir: Path, md: str):
    md_path = out_dir / "Description.md"
    lines = [md]
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_json(out_dir: Path, data: dict, filename: str = "technique.json") -> Path:
    """Write a JSON file in the given directory with pretty formatting.

    Returns the path to the written file.
    """
    json_path = out_dir / filename
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(data, jf, indent=2, ensure_ascii=False)
    return json_path

def collect_subtechniques(parent: dict, subtechniques_by_parent: Dict[str, List[dict]]) -> List[dict]:
    parent_ref = parent.get("id") or ""
    subs = subtechniques_by_parent.get(parent_ref, [])
    return sorted(subs, key=lambda o: get_external_id(o) or o.get("name", ""))

def collect_subtechniques_json(subtechniques: Optional[List[Tuple[str, str]]]) -> List[dict]:
    """
    Accepts a list of (id, name) tuples and returns a list of dicts
    with keys {"id", "name"}. Returns an empty list if None/empty.
    """
    if not subtechniques:
        return []
    return [{"id": st_id, "name": st_name} for st_id, st_name in subtechniques]

def fetch_atomic_red_tests(tid: str, out_dir: Path) -> Optional[Path]:
    url = ATOMIC_RED_URL_TMPL.format(tid=tid)
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200 and r.text:
            path = out_dir / "atomic-red-tests.md"
            with open(path, "w", encoding="utf-8") as f:
                f.write(r.text)
            return path
        # 404 means no atomic tests for this technique
        return None
    except Exception:
        return None

def fetch_atomic_red_tests_json(tid: str, out_dir: Path) -> Optional[Path]:
    """
    Fetch Atomic Red Team tests and store as JSON with raw markdown content.
    Returns the path to the JSON file if written, otherwise None.
    """
    url = ATOMIC_RED_URL_TMPL.format(tid=tid)
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200 and r.text:
            data = {
                "technique_id": tid,
                "url": url,
                "found": True,
                "raw_markdown": r.text,
            }
            return write_json(out_dir, data, filename="atomic-red-tests.json")
        return None
    except Exception:
        return None

def flatten_json(obj: Any, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """Recursively flatten a nested JSON-like structure.

    - Dicts become dotted key paths.
    - Lists are flattened with numeric indices as path segments.
    - Scalar values are preserved exactly (strings, numbers, bool, None).

    Examples:
      {"a": {"b": 1}} => {"a.b": 1}
      {"a": [ {"b": 1}, 2 ]} => {"a.0.b": 1, "a.1": 2}
    """
    items: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            items.update(flatten_json(v, new_key, sep))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{parent_key}{sep}{i}" if parent_key else str(i)
            items.update(flatten_json(v, new_key, sep))
    else:
        # Preserve scalar values exactly as they are
        items[parent_key] = obj
    return items


def find_bases() -> List[Path]:
    """Find existing export directories for technique.json files using underscore or hyphen naming."""
    # Resolve both underscore and hyphen variants, relative to:
    # - current working directory
    # - this script's directory
    script_dir = Path(__file__).resolve().parent
    candidates = [
        # From where the script is executed
        Path("attack_techniques"),
        Path("attack-techniques"),
        # Explicitly from the CWD
        Path.cwd() / "attack_techniques",
        Path.cwd() / "attack-techniques",
        # Relative to the script directory (useful if run from elsewhere)
        script_dir / "attack_techniques",
        script_dir / "attack-techniques",
        # Project-root style when script is under implementations-pipeline/
        script_dir.parent / "attack_techniques",
        script_dir.parent / "attack-techniques",
    ]
    seen = set()
    bases: List[Path] = []
    for dir in candidates:
        try:
            r_dir = dir.resolve()
        except Exception:
            r_dir = dir
        if dir.exists() and r_dir not in seen:
            bases.append(dir)
            seen.add(r_dir)
    return bases

def collect_technique_files(bases: Iterable[Path], tid: str) -> List[Path]:
    files: List[Path] = []
    for base in bases:
        matches = [
            f for f in base.rglob("technique.json")
            if f.parent.name.startswith(tid)
        ]
        files.extend(sorted(matches))
    # Deduplicate by resolved path
    unique = {}
    for f in files:
        try:
            unique[str(f.resolve())] = f
        except Exception:
            unique[str(f)] = f
    return list(unique.values())


def markdown_extractor(md_path: str):
    """Extract Atomic Red Team tests from Markdown text.
    Required fields: label, external_id, and description.
    """
    markdown_text = Path(md_path).read_text(encoding="utf-8")
    
    # Define which headers to track and split on
    headers_to_split_on = [
        ("#", "1"),
        ("##", "2"),
        ("### Atomic Test", "3"),
        ("####", "4"),
    ]
    atomic_tests = []
    splitter = MarkdownHeaderTextSplitter(headers_to_split_on=headers_to_split_on)
    chunks = splitter.split_text(markdown_text)
    for chunk in chunks:
        if "3" in chunk.metadata and "4" not in chunk.metadata:
            header = chunk.metadata.get("3")
            match = re.search(r"#\d+:\s*(.*)", header)
            if match:
                header_name = match.group(1)
                
            description_match = re.search(
                r"^(.*?)\n\s*\*\*Supported Platforms:\*\*",
                chunk.page_content,
                re.DOTALL
            )
            if description_match:
                description = description_match.group(1).strip()

            platform_match = re.search(
                r"\*\*Supported Platforms:\*\*\s*(.+)",
                chunk.page_content
            )
            if platform_match:
                supported_platform = platform_match.group(1).strip()

            guid_match = re.search(
                r"\*\*auto_generated_guid:\*\*\s*`([^`]+)`",
                chunk.page_content
            )
            if guid_match:
                external_id = guid_match.group(1).strip()
            
            atomic_tests.append({
                "label": header_name,
                "external_id": external_id,
                "description": description
            })
    return atomic_tests

def load_atomic_into_json(atomic_tests, tech_path):
    """Given a list of atomic tests and the path to technique.json, load them into technique.json
    
    Format of atomic tests in each entry:
    {
        label: str,
        external_id: str,
        description: str
    }
    """
    
    # Open the json
    with open(tech_path, "r", encoding="utf-8") as f:
        technique_json = json.load(f)

    # Modify the json
        technique_json["atomic_tests"] = atomic_tests

    # Save the json
    with open(tech_path, "w", encoding="utf-8") as f:
        print("Writing atomic tests into technique.json")
        json.dump(technique_json, f, indent=2)
        
    return 1

def main():
    ap = argparse.ArgumentParser(description="Export ATT&CK techniques and subtechniques to directories with markdown and Atomic Red Team tests.")
    ap.add_argument("techniques", nargs="+", help="ATT&CK technique IDs (e.g. T1053, T1059 T1003.001)")
    ap.add_argument("--jsonl", type=parse_bool, default=True, metavar="{True,False}", help="Create JSONL files with technique data (case-insensitive; default: True)")
    ap.add_argument("--url", default=ATTACK_JSON_URL, help="Source ATT&CK STIX JSON URL")
    ap.add_argument("--out", default="attack-techniques", help="Output directory")
    args = ap.parse_args()

    bundle = load_attack_json(args.url)
    by_id, attack_patterns_by_tid, subtechniques_by_parent, uses_by_target, tactic_map = build_indexes(bundle)

    out_base = Path(args.out)
    out_base.mkdir(parents=True, exist_ok=True)

    # Normalize input IDs (uppercase, strip)
    requested: List[str] = []
    for t in args.techniques:
        t = t.strip().upper()
        if t.startswith("TA"):
            # ATT&CK Tactic - extract techniques
            t_shortname = tactic_map[t]
            tid_extracted = []
            for tid, obj, in attack_patterns_by_tid.items():
                # Only interested in attack patterns
                if obj.get("type") != "attack-pattern":
                    continue
                # Only interested in techniques
                if obj.get("x_mitre_is_subtechnique", False):
                    continue
                
                phases = obj.get("kill_chain_phases",[])
                
                if any(
                    p.get("kill_chain_name") == "mitre-attack" and
                    p.get("phase_name") == t_shortname
                    for p in phases
                ):
                    tid_extracted.append(tid)
            
            # Print results and append
            print(f"Extracted: {tid_extracted} from {t}")
            for tid in tid_extracted:
                requested.append(tid)
            continue
                        
        elif not t.startswith("T"):
            print(f"Skipping '{t}': not a technique ID", file=sys.stderr)
            continue
        else:
            requested.append(t)

    processed: set = set()

    for tid in requested:
        tech = attack_patterns_by_tid.get(tid)
        print(f"Processing technique {tid}")
        if not tech:
            print(f"Technique {tid} not found in dataset", file=sys.stderr)
            continue

        to_process: List[dict] = []
        to_process.append(tech)

        # If top-level technique, also include subtechniques
        subs: List[dict] = []
        if "." not in tid and not tech.get("x_mitre_is_subtechnique"):
            # Primary: use parent->subtechniques mapping
            subs = collect_subtechniques(tech, subtechniques_by_parent)
            # Fallback: prefix match on external IDs in case parent mapping is missing
            prefix_subs = [
                obj for sub_tid, obj in attack_patterns_by_tid.items()
                if sub_tid.startswith(tid + ".")
            ]
            # Combine and deduplicate while preserving order
            seen_ids = set(id(o) for o in subs)
            for o in prefix_subs:
                if id(o) not in seen_ids:
                    subs.append(o)
                    seen_ids.add(id(o))
            to_process.extend(subs)

        for obj in to_process:
            obj_tid = get_external_id(obj) or obj.get("id")
            if obj_tid in processed:
                continue
            processed.add(obj_tid)
            out_dir = ensure_dir_for_tech(obj, out_base)
            # Build subtechnique list (id, name) for top-level technique only
            sub_list: Optional[List[Tuple[str, str]]] = None
            if not obj.get("x_mitre_is_subtechnique"):
                # Use previously collected subs for this technique
                # Note: subs variable includes any deduped subtechniques for the parent
                if obj is tech:
                    sub_list = []
                    for s in subs:
                        st_id = get_external_id(s) or s.get("id", "")
                        st_name = s.get("name", "")
                        if st_id:
                            sub_list.append((st_id, st_name))
            md, _procedures = extract_technique_markdown(obj, by_id, uses_by_target, sub_list)
            write_markdown(out_dir, md)
            # Also output JSON for each technique and sub-technique
            try:
                data = extract_technique_json(obj, by_id, uses_by_target, sub_list)
                write_json(out_dir, data, filename="technique.json")
                # Also emit subtechniques.json for top-level techniques when available
                if sub_list is not None:
                    subs_json = collect_subtechniques_json(sub_list)
                    write_json(out_dir, {"subtechniques": subs_json}, filename="subtechniques.json")
            except Exception as e:
                print(f"Failed to write JSON for {obj_tid}: {e}", file=sys.stderr)
            tid_for_atomic = get_external_id(obj)
            if tid_for_atomic:
                fetch_atomic_red_tests(tid_for_atomic, out_dir)
                fetch_atomic_red_tests_json(tid_for_atomic, out_dir)
                # Import atomic tests to technique.json only if atomic tests are available
                if (out_dir / "atomic-red-tests.md").exists():
                    atomic_tests = markdown_extractor(out_dir / "atomic-red-tests.md")
                    load_atomic_into_json(atomic_tests, out_dir / "technique.json")
                print(f"Wrote {out_dir}")

        # Create JSONL by default for each tid
        if args.jsonl:
            bases = find_bases()
            if not bases:
                print(
                    "No base directory found. Looked for 'attack-techniques' variants.",
                    file=sys.stderr,
                )
                return 1

            tech_files = collect_technique_files(bases,tid)
            if not tech_files:
                print(
                    f"No technique.json files found under: {', '.join(str(b) for b in bases)}",
                    file=sys.stderr,
                )
                return 1
            print(len(tech_files))

            out_path = Path.cwd() / f"{tid}.jsonl"
            written = 0
            with out_path.open("w", encoding="utf-8") as out_f:
                for path in tech_files:
                    try:
                        with path.open("r", encoding="utf-8") as f:
                            data = json.load(f)
                        flat = flatten_json(data)
                        json.dump(flat, out_f, ensure_ascii=False)
                        out_f.write("\n")
                        written += 1
                    except Exception as e:
                        print(f"Skipping {path} due to error: {e}", file=sys.stderr)

            print(f"Wrote {written} records to {out_path}")
        else:
            print(f"No JSONL Generated for {tid}")

if __name__ == "__main__":
    main()
