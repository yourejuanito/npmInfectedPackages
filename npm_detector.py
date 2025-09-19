#!/usr/bin/env python3
"""
npm_shai_hulud_detector.py

Scan a macOS (or Linux) machine for installed Node.js packages and compare them
against a CSV list of impacted packages (e.g., from the "shai-hulud" npm incident).

Created by Juan Garcia 
"""

import argparse
import csv
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

FINDINGS_CSV = "/Library/Application Support/Security/intel/npm_findings.csv"


def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def load_impacted_packages(csv_path: str) -> List[Dict[str, str]]:
    impacted = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = {h.lower(): h for h in reader.fieldnames or []}
        name_key = headers.get("package_name") or headers.get("name") or "package_name"
        version_key = headers.get("version") or "version"
        for row in reader:
            pkg_name = row.get(name_key, "").strip()
            if not pkg_name:
                continue
            impacted.append({
                "package_name": pkg_name,
                "version": (row.get(version_key, "") or "").strip()
            })
    return impacted


def get_global_npm_list() -> Dict[str, str]:
    code, out, err = run(["npm", "-g", "ls", "--depth=0", "--json"])
    if code != 0 and not out:
        return {}
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        json_start = out.find("{")
        if json_start != -1:
            data = json.loads(out[json_start:])
        else:
            return {}
    deps = data.get("dependencies", {}) or {}
    return {name: info.get("version", "") for name, info in deps.items()}


def discover_package_json_roots(roots: List[str]) -> List[Path]:
    found = []
    for r in roots:
        root = Path(os.path.expanduser(r)).resolve()
        if not root.exists():
            continue
        for p in root.rglob("package.json"):
            if "node_modules" in p.parts:
                continue
            found.append(p.parent)
    return found


def get_local_npm_list(project_dir: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    node_modules = project_dir / "node_modules"
    if node_modules.is_dir():
        for pkgdir in node_modules.iterdir():
            if pkgdir.name.startswith("."):
                continue
            if pkgdir.is_dir() and pkgdir.name.startswith("@"):
                for sub in pkgdir.iterdir():
                    pkg_json = sub / "package.json"
                    if pkg_json.is_file():
                        try:
                            with pkg_json.open("r", encoding="utf-8") as f:
                                meta = json.load(f)
                            name = meta.get("name", sub.name)
                            version = meta.get("version", "")
                            deps[name] = version
                        except Exception:
                            pass
            else:
                pkg_json = pkgdir / "package.json"
                if pkg_json.is_file():
                    try:
                        with pkg_json.open("r", encoding="utf-8") as f:
                            meta = json.load(f)
                        name = meta.get("name", pkgdir.name)
                        version = meta.get("version", "")
                        deps[name] = version
                    except Exception:
                        pass
        if deps:
            return deps

    code, out, err = run(["npm", "ls", "--depth=0", "--json"])
    if code != 0 and not out:
        return {}
    try:
        data = json.loads(out) if out else {}
    except json.JSONDecodeError:
        json_start = out.find("{")
        if json_start != -1:
            data = json.loads(out[json_start:])
        else:
            return {}
    local_deps = data.get("dependencies", {}) or {}
    return {name: info.get("version", "") for name, info in local_deps.items()}


def compare(impacted: List[Dict[str, str]], installed: Dict[str, str], location: str) -> List[Dict[str, str]]:
    findings = []
    impacted_set = {i["package_name"] for i in impacted}
    for name, ver in installed.items():
        if name in impacted_set:
            expected = next((i.get("version", "") for i in impacted if i["package_name"] == name), "")
            findings.append({
                "package_name": name,
                "installed_version": ver,
                "impacted_version_from_csv": expected,
                "location": location
            })
    return findings


def write_findings_csv(findings: List[Dict[str, str]]) -> None:
    os.makedirs("/Library/Application Support/Security/intel", exist_ok=True)
    with open(FINDINGS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["package_name", "installed_version", "impacted_version_from_csv", "location"])
        writer.writeheader()
        for row in findings:
            writer.writerow(row)


def npm_available() -> bool:
    code, out, err = run(["npm", "-v"])
    return code == 0 and bool(out.strip())


def main():
    ap = argparse.ArgumentParser(description="Compare installed npm packages to impacted CSV list.")
    ap.add_argument("--csv", required=True, help="Path to impacted packages CSV (must include 'package_name' column).")
    ap.add_argument("--roots", nargs="*", default=[], help="Optional directories to scan recursively for local projects (package.json).")
    args = ap.parse_args()

    if not os.path.isfile(args.csv):
        print(f"[!] CSV not found: {args.csv}", file=sys.stderr)
        sys.exit(1)

    impacted = load_impacted_packages(args.csv)
    if not impacted:
        print("[!] No impacted package names found in CSV.", file=sys.stderr)
        sys.exit(1)

    if not npm_available():
        write_findings_csv([])
        print("npm is not installed on this machine. Wrote header-only report to:", FINDINGS_CSV)
        sys.exit(0)

    findings: List[Dict[str, str]] = []

    global_installed = get_global_npm_list()
    findings += compare(impacted, global_installed, "global")

    roots = args.roots or []
    if roots:
        projects = discover_package_json_roots(roots)
        for proj in projects:
            os.chdir(proj)
            local_installed = get_local_npm_list(proj)
            findings += compare(impacted, local_installed, f"local:{proj}")

    write_findings_csv(findings)

    if findings:
        print("== MATCHES FOUND ==")
        for f in findings:
            print(f"- {f['package_name']} | installed={f['installed_version']} | expected(csv)={f['impacted_version_from_csv']} | where={f['location']}")
        print(f"\nWrote detailed report: {FINDINGS_CSV}")
    else:
        print("No impacted packages found globally or in scanned roots.")
        print(f"Wrote report to: {FINDINGS_CSV}")


if __name__ == "__main__":
    main()
