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
import re
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


def _alert_severity(rule: dict) -> str:
    if rule.get("security_severity_level"):
        return rule["security_severity_level"].lower()
    level = (rule.get("severity") or "warning").lower()
    return SARIF_LEVEL.get(level, "low")


def _alert_finding(alert: dict) -> dict:
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    message = (instance.get("message") or {}).get("text") or ""
    start = location.get("start_line")
    return {
        "source": "code-scanning",
        "tool": (alert.get("tool") or {}).get("name") or "unknown",
        "rule": rule.get("id") or rule.get("name") or "unknown",
        "title": rule.get("description") or rule.get("name") or "",
        "message": message.strip(),
        "severity": _alert_severity(rule),
        "path": location.get("path") or "",
        "start_line": start,
        "end_line": location.get("end_line") or start,
        "tags": rule.get("tags") or [],
        "url": alert.get("html_url") or "",
    }


def normalise_code_scanning(alerts: list[dict]) -> list[dict]:
    return [_alert_finding(alert) for alert in alerts]


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


def _sonar_path(component: str) -> str:
    return component.split(":", 1)[1] if ":" in component else component


def _sonar_issue(project_key: str, issue: dict) -> dict:
    text_range = issue.get("textRange") or {}
    line = issue.get("line")
    return {
        "source": "sonarcloud",
        "tool": "SonarCloud",
        "rule": issue.get("rule") or "unknown",
        "title": (issue.get("type") or "").replace("_", " ").title(),
        "message": issue.get("message") or "",
        "severity": SONAR_SEVERITY.get(issue.get("severity") or "MAJOR", "medium"),
        "path": _sonar_path(issue.get("component") or ""),
        "start_line": text_range.get("startLine") or line,
        "end_line": text_range.get("endLine") or line,
        "tags": issue.get("tags") or [],
        "url": f"https://sonarcloud.io/project/issues?id={project_key}&open={issue.get('key', '')}",
    }


def _sonar_hotspot(project_key: str, hotspot: dict) -> dict:
    text_range = hotspot.get("textRange") or {}
    line = hotspot.get("line")
    category = hotspot.get("securityCategory", "")
    return {
        "source": "sonarcloud",
        "tool": "SonarCloud (hotspot)",
        "rule": hotspot.get("ruleKey") or "unknown",
        "title": f"Security hotspot: {category}".strip(),
        "message": hotspot.get("message") or "",
        "severity": SONAR_HOTSPOT.get(hotspot.get("vulnerabilityProbability") or "LOW", "low"),
        "path": _sonar_path(hotspot.get("component") or ""),
        "start_line": text_range.get("startLine") or line,
        "end_line": text_range.get("endLine") or line,
        "tags": [],
        "url": f"https://sonarcloud.io/project/security_hotspots?id={project_key}&hotspots={hotspot.get('key', '')}",
    }


def normalise_sonar(project_key: str, issues: list[dict], hotspots: list[dict]) -> list[dict]:
    return [_sonar_issue(project_key, i) for i in issues] + [_sonar_hotspot(project_key, h) for h in hotspots]


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


def _render_summary(groups: list[dict], meta: dict) -> list[str]:
    out = ["## Summary", "", "| Severity | Locations |", "|---|---|"]
    by_severity = Counter(g["severity"] for g in groups)
    out.extend(f"| {name} | {by_severity[name]} |" for name in SEVERITY_ORDER if by_severity.get(name))
    out.extend(["", "| Tool | Findings |", "|---|---|"])
    by_tool = Counter(f["tool"] for g in groups for f in g["findings"])
    out.extend(f"| {tool} | {count} |" for tool, count in by_tool.most_common())
    out.append("")
    if meta.get("errors"):
        out.extend(["**Sources that could not be read:**", ""])
        out.extend(f"- {error}" for error in meta["errors"])
        out.append("")
    dashboards = ", ".join(f"[{name}]({url})" for name, url in EXTERNAL_DASHBOARDS)
    out.extend([f"Not included (results stay in each service's dashboard): {dashboards}.", ""])
    return out


def _location_label(group: dict) -> str:
    where = group["path"] or "(no source location)"
    if group["start_line"]:
        where += f":{group['start_line']}"
        if group["end_line"] and group["end_line"] != group["start_line"]:
            where += f"-{group['end_line']}"
    return where


def _render_finding(finding: dict) -> list[str]:
    title = f" ({finding['title']})" if finding["title"] else ""
    out = [f"- **{finding['tool']}** `{finding['rule']}`{title}, {finding['severity']}"]
    if finding["message"]:
        out.append(f"  - {' '.join(finding['message'].split())}")
    if finding["url"]:
        out.append(f"  - {finding['url']}")
    return out


def _render_group(index: int, group: dict, root: Path, context: int) -> list[str]:
    out = [f"### {index}. [{group['severity'].upper()}] `{_location_label(group)}`", ""]
    if len(group["tools"]) > 1:
        out.extend([f"Reported by {len(group['tools'])} tools: {', '.join(group['tools'])}.", ""])
    for finding in group["findings"]:
        out.extend(_render_finding(finding))
    snippet = excerpt(root, group["path"], group["start_line"], group["end_line"], context)
    if snippet:
        out.extend(["", f"```{fence_language(group['path'])}", snippet, "```"])
    out.append("")
    return out


def render_markdown(groups: list[dict], meta: dict, root: Path, context: int) -> str:
    out = [
        f"# Security report: {meta['repo']}",
        "",
        f"Generated {meta['generated']} from commit `{meta['commit']}`. "
        f"{meta['finding_count']} open findings at {len(groups)} locations "
        f"(minimum severity: {meta['min_severity']}).",
        "",
        PREAMBLE.format(commit=meta["commit"]),
    ]
    out.extend(_render_summary(groups, meta))
    out.extend(["## Findings", ""])
    for index, group in enumerate(groups, 1):
        out.extend(_render_group(index, group, root, context))
    return "\n".join(out)


# -------------------------------------------------------------------- main

WORKSPACE = Path.cwd().resolve()


def workspace_path(value: str) -> Path:
    """An argparse type: a path that must stay inside the working directory."""
    candidate = (WORKSPACE / value).resolve()
    if not candidate.is_relative_to(WORKSPACE):
        raise argparse.ArgumentTypeError(f"{value!r} is outside the working directory")
    return candidate


def output_dir(value: str) -> Path:
    """An argparse type: "." or a plain directory name created in the working directory."""
    if value == ".":
        return WORKSPACE
    if value == ".." or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise argparse.ArgumentTypeError(f"{value!r} must be a plain directory name")
    return workspace_path(value)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
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
    parser.add_argument("--root", type=workspace_path, default=WORKSPACE,
                        help="checked-out repository root, for excerpts (inside the working directory)")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "HEAD"))
    parser.add_argument("--out-dir", type=output_dir, default=WORKSPACE,
                        help="directory name for the report, created in the working directory")
    return parser.parse_args(argv)


def collect(args: argparse.Namespace) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    errors: list[str] = []
    if not os.environ.get("GITHUB_TOKEN"):
        errors.append("GitHub code scanning: GITHUB_TOKEN is not set")
    else:
        try:
            findings += normalise_code_scanning(fetch_code_scanning(args.repo, os.environ["GITHUB_TOKEN"]))
        except (OSError, ValueError) as exc:  # URLError is an OSError
            errors.append(f"GitHub code scanning: {exc}")

    if args.sonar_project:
        try:
            findings += fetch_sonar(args.sonar_project, args.include_code_quality)
        except (OSError, ValueError) as exc:
            errors.append(f"SonarCloud: {exc}")

    excluded = {name.lower() for name in args.exclude_tool}
    threshold = SEVERITY_RANK[args.min_severity]
    kept = [
        f for f in findings
        if SEVERITY_RANK.get(f["severity"], 99) <= threshold and f["tool"].lower() not in excluded
    ]
    return kept, errors


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    findings, errors = collect(args)
    groups = group_by_location(findings)
    meta = {
        "repo": args.repo,
        "commit": args.commit,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "min_severity": args.min_severity,
        "finding_count": len(findings),
        "errors": errors,
    }
    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(groups, meta, args.root, args.context)
    (out_dir / "security-report.md").write_text(markdown, encoding="utf-8")
    report = json.dumps({"meta": meta, "locations": groups}, indent=2)
    (out_dir / "security-report.json").write_text(report, encoding="utf-8")

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
