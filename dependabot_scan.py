#!/usr/bin/env python3
"""Run-once Dependabot alert scanner (CLI shim).

The implementation lives in the ``dependabot_scanner`` package; this thin
wrapper preserves the ``python dependabot_scan.py`` entry point used by the
scheduled GitHub Actions workflow and the README.

Fetches open Dependabot alerts for a repository, categorizes them, applies a
dispatch policy, and hands the qualifying ones to Devin. Each dispatched Devin
session is responsible for opening the fix PR in the affected repository itself
(that is where the vulnerable manifest lives).

Usage:
    python dependabot_scan.py            # scan and dispatch
    python dependabot_scan.py --dry-run  # scan and print decisions, dispatch nothing
"""
from dependabot_scanner.cli import main

if __name__ == "__main__":
    main()
