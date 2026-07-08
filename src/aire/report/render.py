"""Render an AuditReport as JSON (canonical), Markdown, or HTML.

Security notes for the HTML renderer:

- Report content is **untrusted** (summaries can embed attacker-controlled
  prompt excerpts, session ids are caller-chosen strings). Jinja2 autoescape
  is force-enabled and there is a regression test feeding hostile input.
- The document is fully self-contained: inline CSS, no scripts, no external
  resources — it renders identically in an air-gapped environment and never
  phones home.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from aire.report.models import AuditReport

_TEMPLATES = Path(__file__).parent / "templates"


def to_json(report: AuditReport) -> str:
    return report.model_dump_json(indent=2)


def to_markdown(report: AuditReport) -> str:
    lines = [
        f"# {report.title}",
        "",
        f"- Generated: {report.generated_at} (aire {report.aire_version})",
        f"- Evidence store: `{report.store_path}`"
        + (f" (session filter: `{report.session_filter}`)" if report.session_filter else ""),
        f"- Events in scope: {report.total_events}",
        "",
        "## Evidence chain",
        "",
        (
            f"**INTACT** — {report.chain.events_verified} event(s) verified"
            if report.chain.ok
            else f"**BROKEN at seq {report.chain.first_bad_seq}** — {report.chain.reason}"
        ),
        "",
        "## Overall risk",
        "",
        f"**{report.overall_risk_level.value.upper()}** (score {report.overall_risk_score})"
        + (
            " — severity totals: "
            + ", ".join(f"{k}: {v}" for k, v in sorted(report.severity_totals.items()))
            if report.severity_totals
            else " — no findings"
        ),
        "",
    ]
    for session in report.sessions:
        lines += [
            f"## Session `{_md(session.session_id)}` — risk "
            f"{session.risk_level.value.upper()} ({session.risk_score})",
            "",
            "| Severity | Origin | Finding | Evidence | Frameworks |",
            "|---|---|---|---|---|",
        ]
        for f in session.findings:
            evidence = "; ".join(
                f"`{eid}` ({h[:12]}…)"
                for eid, h in zip(f.source_event_ids, f.source_event_hashes, strict=False)
            ) or f"`{f.record_event_id}`"
            cites = "; ".join(
                f"{c.framework} {c.control_id} ({c.title})" for c in f.citations
            )
            if f.unresolved_refs:
                cites += " ⚠ unresolved: " + ", ".join(f.unresolved_refs)
            verdict = f" [{f.verdict}]" if f.verdict else ""
            lines.append(
                f"| {f.severity.value}{verdict} | {_md(f.origin)} | "
                f"{_md(f.summary)} | {evidence} | {_md(cites)} |"
            )
        lines.append("")
    if report.recommendations:
        lines += ["## Recommendations", ""]
        lines += [f"- {_md(r)}" for r in report.recommendations]
        lines.append("")
    lines += [
        "---",
        "",
        "*Findings are statements of detected conditions with evidence pointers — "
        "not a compliance certification. Evidence event ids and hashes refer to the "
        "append-only, hash-chained store; verify with `aire verify`.*",
    ]
    return "\n".join(lines)


def to_html(report: AuditReport) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        autoescape=True,  # untrusted content — non-negotiable
    )
    return env.get_template("report.html.j2").render(report=report)


def _md(text: str) -> str:
    """Neutralize characters that would break Markdown table structure."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()
