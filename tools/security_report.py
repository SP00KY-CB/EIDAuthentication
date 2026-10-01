#!/usr/bin/env python3
"""Collect open security findings into one report for AI-assisted remediation.

Sources
  * GitHub code scanning alerts: every tool that uploads SARIF to this
    repository (CodeQL, Corgea, MegaLinter's linters, KICS, BinSkim,
    Scorecard, Gitleaks, Kingfisher, 2MS, ...).
  * SonarCloud: open vulnerabilities and bugs (code smells with
    --include-code-quality) and security hotspots still to review.

Findings reported at the same file and line by several tools are merged
into one entry that lists every tool, since agreement between tools is
a useful signal. Each entry carries a source excerpt from the checked-out
tree so the report can be read without the repository at hand.

Outputs
  security-report.md    Markdown, ordered by severity, with a preamble
                        that tells an AI assistant how to work through it.
  security-report.json  The same findings, machine-readable.

Uses only the Python standard library. In CI the GitHub token comes from
GITHUB_TOKEN; locally, any token with security_events read access works.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "note"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

# Code scanning: security rules carry security_severity_level; other rules
# only have the SARIF level (error / warning / note).
SARIF_LEVEL = {"error": "medium", "warning": "low", "note": "note", "none": "note"}

SONAR_SEVERITY = {
    "BLOCKER": "critical",
    "CRITICAL": "high",
    "MAJOR": "medium",
    "MINOR": "low",
    "INFO": "note",
}
SONAR_HOTSPOT = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# Dashboards whose results stay behind a login; listed in the report so
# nothing is silently missing.
EXTERNAL_DASHBOARDS = [
    ("Snyk", "https://app.snyk.io/org/sp00ky-cb/project/936e041e-19b8-47c5-a278-2a090b81a88c"),
    ("Coverity Scan", "https://scan.coverity.com/projects/sp00ky-cb-openaccesseid"),
    ("Aikido", "https://app.aikido.dev/repositories/2594845"),
    ("Xygeni", "https://in.xygeni.io/dashboard"),
    ("GitGuardian", "https://dashboard.gitguardian.com"),
    ("Arnica", "https://app.arnica.io"),
    ("Kusari Inspector", "https://console.us.kusari.cloud"),
]

PREAMBLE = """\
## How to use this report (instructions for an AI assistant)

You are helping remediate security findings in **OpenAccess EID**, a C/C++
Win32 smart-card logon component: an LSA authentication package that runs
inside `lsass.exe`, a credential provider loaded by LogonUI, and supporting
tools and an NSIS installer. Code on this path runs as SYSTEM, so memory
safety, input validation at trust boundaries, secret handling (PINs,
passwords, keys must be wiped with SecureZeroMemory) and DLL loading are
the areas that matter most.

For each finding:

1. **Verify it against the code** before changing anything. Static
   analysers report false positives; say so plainly when a finding does not
   hold, and explain why (for example, the length is already checked a few
   lines earlier).
2. **Fix real issues with the smallest correct change.** Do not weaken an
   existing check, disable a warning, or suppress a rule to make a finding
   go away.
3. **Work in severity order**, critical first. Entries reported by several
   tools at the same location are more likely to be real.
4. **Group related fixes** (same function, same root cause) and note any
   behaviour change, API change or new test that the fix needs.
5. The build uses Visual Studio 2022 (v143, `/Qspectre`, `/W4`, `/sdl`); keep
   fixes compatible with it and with the existing coding style.

Line numbers refer to commit `{commit}`.
"""


# --------------------------------------------------------------------- HTTP

def _get_json(url: str, token: str | None = None) -> tuple[object, dict]:
    headers = {"Accept": "application/json", "User-Agent": "openaccesseid-security-report"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - https URLs built below
        return json.load(response), dict(response.headers)


def _next_link(headers: dict) -> str | None:
    link = headers.get("Link") or headers.get("link") or ""
    for part in link.split(","):
        segment = part.strip()
        if segment.endswith('rel="next"'):
            return segment[segment.find("<") + 1 : segment.find(">")]
    return None


# ------------------------------------------------------------ code scanning

def fetch_code_scanning(repo: str, token: str, api: str = "https://api.github.com") -> list[dict]:
    url = f"{api}/repos/{repo}/code-scanning/alerts?state=open&per_page=100"
    alerts: list[dict] = []
    while url:
        page, headers = _get_json(url, token)
        alerts.extend(page)  # type: ignore[arg-type]
        url = _next_link(headers)
    return alerts


def normalise_code_scanning(alerts: list[dict]) -> list[dict]:
    findings = []
    for alert in alerts:
        rule = alert.get("rule") or {}
        instance = alert.get("most_recent_instance") or {}
        location = instance.get("location") or {}
        severity = rule.get("security_severity_level") or SARIF_LEVEL.get(
            (rule.get("severity") or "warning").lower(), "low"
        )
        findings.append(
            {
                "source": "code-scanning",
                "tool": (alert.get("tool") or {}).get("name") or "unknown",
                "rule": rule.get("id") or rule.get("name") or "unknown",
                "title": rule.get("description") or rule.get("name") or "",
                "message": ((instance.get("message") or {}).get("text") or "").strip(),
                "severity": severity.lower(),
                "path": location.get("path") or "",
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line") or location.get("start_line"),
                "tags": rule.get("tags") or [],
                "url": alert.get("html_url") or "",
            }
        )
    return findings


# ---------------------------------------------------------------- SonarCloud

def fetch_sonar(project_key: str, include_code_quality: bool,
                base: str = "https://sonarcloud.io") -> list[dict]:
    types = "VULNERABILITY,BUG" + (",CODE_SMELL" if include_code_quality else "")
    issues: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode(
            {"componentKeys": project_key, "resolved": "false", "types": types, "ps": 500, "p": page}
        )
        data, _ = _get_json(f"{base}/api/issues/search?{query}")
        batch = data.get("issues", [])  # type: ignore[union-attr]
        issues.extend(batch)
        total = (data.get("paging") or {}).get("total", 0)  # type: ignore[union-attr]
        if not batch or len(issues) >= total or page * 500 >= 10000:
            break
        page += 1

    hotspots: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode(
            {"projectKey": project_key, "status": "TO_REVIEW", "ps": 500, "p": page}
        )
        data, _ = _get_json(f"{base}/api/hotspots/search?{query}")
        batch = data.get("hotspots", [])  # type: ignore[union-attr]
        hotspots.extend(batch)
        total = (data.get("paging") or {}).get("total", 0)  # type: ignore[union-attr]
        if not batch or len(hotspots) >= total:
            break
        page += 1
    return normalise_sonar(project_key, issues, hotspots)


def normalise_sonar(project_key: str, issues: list[dict], hotspots: list[dict]) -> list[dict]:
    def path_of(component: str) -> str:
        return component.split(":", 1)[1] if ":" in component else component

    findings = []
    for issue in issues:
        text_range = issue.get("textRange") or {}
        findings.append(
            {
                "source": "sonarcloud",
                "tool": "SonarCloud",
                "rule": issue.get("rule") or "unknown",
                "title": (issue.get("type") or "").replace("_", " ").title(),
                "message": issue.get("message") or "",
                "severity": SONAR_SEVERITY.get(issue.get("severity") or "MAJOR", "medium"),
                "path": path_of(issue.get("component") or ""),
                "start_line": text_range.get("startLine") or issue.get("line"),
                "end_line": text_range.get("endLine") or issue.get("line"),
                "tags": issue.get("tags") or [],
                "url": f"https://sonarcloud.io/project/issues?id={project_key}&open={issue.get('key', '')}",
            }
        )
    for hotspot in hotspots:
        text_range = hotspot.get("textRange") or {}
        findings.append(
            {
                "source": "sonarcloud",
                "tool": "SonarCloud (hotspot)",
                "rule": hotspot.get("ruleKey") or "unknown",
                "title": f"Security hotspot: {hotspot.get('securityCategory', '')}".strip(),
                "message": hotspot.get("message") or "",
                "severity": SONAR_HOTSPOT.get(hotspot.get("vulnerabilityProbability") or "LOW", "low"),
                "path": path_of(hotspot.get("component") or ""),
                "start_line": text_range.get("startLine") or hotspot.get("line"),
                "end_line": text_range.get("endLine") or hotspot.get("line"),
                "tags": [],
                "url": f"https://sonarcloud.io/project/security_hotspots?id={project_key}&hotspots={hotspot.get('key', '')}",
            }
        )
    return findings


# ------------------------------------------------------------------ report

def group_by_location(findings: list[dict]) -> list[dict]:
    """Merge findings at the same file and line; keep every tool's view."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for finding in findings:
        key = (finding["path"], finding["start_line"]) if finding["path"] else (None, id(finding))
        groups[key].append(finding)

    merged = []
    for (path, line), items in groups.items():
        items.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 99))
        tools = sorted({f["tool"] for f in items})
        merged.append(
            {
                "path": path or "",
                "start_line": line if path else None,
                "end_line": max((f["end_line"] or f["start_line"] or 0) for f in items) or None,
                "severity": items[0]["severity"],
                "tools": tools,
                "findings": items,
            }
        )
    merged.sort(
        key=lambda g: (
            SEVERITY_RANK.get(g["severity"], 99),
            -len(g["tools"]),
            g["path"],
            g["start_line"] or 0,
        )
    )
    return merged


def excerpt(root: Path, path: str, start: int | None, end: int | None, context: int) -> str | None:
    if not path or not start:
        return None
    file_path = (root / path).resolve()
    try:
        file_path.relative_to(root.resolve())
    except ValueError:
        return None
    if not file_path.is_file() or file_path.stat().st_size > 5_000_000:
        return None
    raw = file_path.read_bytes()
    if b"\x00" in raw[:8192]:
        return None
    lines = raw.decode("utf-8", errors="replace").splitlines()
    end = end or start
    first = max(1, start - context)
    last = min(len(lines), end + context)
    width = len(str(last))
    out = []
    for number in range(first, last + 1):
        marker = ">" if start <= number <= end else " "
        out.append(f"{marker}{number:>{width}} | {lines[number - 1]}")
    return "\n".join(out) if out else None


def fence_language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".cc": "cpp",
        ".ps1": "powershell", ".yml": "yaml", ".yaml": "yaml", ".nsi": "nsis",
        ".py": "python", ".json": "json", ".xml": "xml", ".md": "markdown",
    }.get(suffix, "")


def render_markdown(groups: list[dict], meta: dict, root: Path, context: int) -> str:
    out = [f"# Security report: {meta['repo']}", ""]
    out.append(
        f"Generated {meta['generated']} from commit `{meta['commit']}`. "
        f"{meta['finding_count']} open findings at {len(groups)} locations "
        f"(minimum severity: {meta['min_severity']})."
    )
    out.append("")
    out.append(PREAMBLE.format(commit=meta["commit"]))

    out.append("## Summary")
    out.append("")
    by_severity = Counter(g["severity"] for g in groups)
    out.append("| Severity | Locations |")
    out.append("|---|---|")
    for name in SEVERITY_ORDER:
        if by_severity.get(name):
            out.append(f"| {name} | {by_severity[name]} |")
    out.append("")
    by_tool = Counter(f["tool"] for g in groups for f in g["findings"])
    out.append("| Tool | Findings |")
    out.append("|---|---|")
    for tool, count in by_tool.most_common():
        out.append(f"| {tool} | {count} |")
    out.append("")
    if meta.get("errors"):
        out.append("**Sources that could not be read:**")
        out.append("")
        for error in meta["errors"]:
            out.append(f"- {error}")
        out.append("")
    out.append(
        "Not included (results stay in each service's dashboard): "
        + ", ".join(f"[{name}]({url})" for name, url in EXTERNAL_DASHBOARDS)
        + "."
    )
    out.append("")

    out.append("## Findings")
    out.append("")
    for index, group in enumerate(groups, 1):
        where = group["path"] or "(no source location)"
        if group["start_line"]:
            where += f":{group['start_line']}"
            if group["end_line"] and group["end_line"] != group["start_line"]:
                where += f"-{group['end_line']}"
        out.append(f"### {index}. [{group['severity'].upper()}] `{where}`")
        out.append("")
        if len(group["tools"]) > 1:
            out.append(f"Reported by {len(group['tools'])} tools: {', '.join(group['tools'])}.")
            out.append("")
        for finding in group["findings"]:
            title = f" ({finding['title']})" if finding["title"] else ""
            out.append(f"- **{finding['tool']}** `{finding['rule']}`{title}, {finding['severity']}")
            if finding["message"]:
                message = " ".join(finding["message"].split())
                out.append(f"  - {message}")
            if finding["url"]:
                out.append(f"  - {finding['url']}")
        snippet = excerpt(root, group["path"], group["start_line"], group["end_line"], context)
        if snippet:
            out.append("")
            out.append(f"```{fence_language(group['path'])}")
            out.append(snippet)
            out.append("```")
        out.append("")
    return "\n".join(out)


# -------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "SP00KY-CB/OpenAccessEID"))
    parser.add_argument("--sonar-project", default="DangerDawgAU_EIDAuthentication")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low",
                        help="drop findings below this severity (default: low, i.e. drop notes)")
    parser.add_argument("--include-code-quality", action="store_true",
                        help="also include SonarCloud code smells")
    parser.add_argument("--exclude-tool", action="append", default=[],
                        help="drop a tool by name (repeatable, case-insensitive)")
    parser.add_argument("--context", type=int, default=4, help="source lines shown around each finding")
    parser.add_argument("--root", default=".", help="checked-out repository root, for excerpts")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "HEAD"))
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--code-scanning-json", help="read alerts from this file instead of the API (testing)")
    parser.add_argument("--sonar-json", help="read SonarCloud issues/hotspots from this file instead of the API (testing)")
    args = parser.parse_args(argv)

    findings: list[dict] = []
    errors: list[str] = []

    if args.code_scanning_json:
        findings += normalise_code_scanning(json.loads(Path(args.code_scanning_json).read_text()))
    else:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            errors.append("GitHub code scanning: GITHUB_TOKEN is not set")
        else:
            try:
                findings += normalise_code_scanning(fetch_code_scanning(args.repo, token))
            except (urllib.error.URLError, OSError, ValueError) as exc:
                errors.append(f"GitHub code scanning: {exc}")

    if args.sonar_json:
        data = json.loads(Path(args.sonar_json).read_text())
        findings += normalise_sonar(args.sonar_project, data.get("issues", []), data.get("hotspots", []))
    elif args.sonar_project:
        try:
            findings += fetch_sonar(args.sonar_project, args.include_code_quality)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append(f"SonarCloud: {exc}")

    excluded = {name.lower() for name in args.exclude_tool}
    threshold = SEVERITY_RANK[args.min_severity]
    findings = [
        f for f in findings
        if SEVERITY_RANK.get(f["severity"], 99) <= threshold and f["tool"].lower() not in excluded
    ]
    groups = group_by_location(findings)

    meta = {
        "repo": args.repo,
        "commit": args.commit,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "min_severity": args.min_severity,
        "finding_count": len(findings),
        "errors": errors,
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    root = Path(args.root)
    (out_dir / "security-report.md").write_text(render_markdown(groups, meta, root, args.context), encoding="utf-8")
    (out_dir / "security-report.json").write_text(
        json.dumps({"meta": meta, "locations": groups}, indent=2), encoding="utf-8"
    )

    by_severity = Counter(g["severity"] for g in groups)
    summary = ", ".join(f"{by_severity[s]} {s}" for s in SEVERITY_ORDER if by_severity.get(s)) or "none"
    print(f"{len(findings)} findings at {len(groups)} locations ({summary}).")
    for error in errors:
        print(f"warning: {error}", file=sys.stderr)
    # A source that could not be read leaves the report incomplete: fail so
    # the workflow run shows it, but the partial report is still written.
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
