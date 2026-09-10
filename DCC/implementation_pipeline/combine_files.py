#!/usr/bin/env python3
"""Combine validated per-technique workbooks without making LLM requests."""

import argparse

from analyze_techniques_llm import merge_excel


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Combine validated ATT&CK T-code Excel workbooks without LLM analysis."
    )
    parser.add_argument(
        "--out",
        default="attack-analysis.xlsx",
        help="Combined workbook path (default: attack-analysis.xlsx)",
    )
    args = parser.parse_args()
    merge_excel(args.out)


if __name__ == "__main__":
    main()
