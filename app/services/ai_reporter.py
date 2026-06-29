import json
import logging
from typing import Any

from app.config import Settings
from app.schemas import Finding
from app.services.owasp import risk_grade

logger = logging.getLogger(__name__)


def _count_by_risk(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        key = f.risk if f.risk in counts else "Informational"
        counts[key] += 1
    return counts


def friendly_category_label(owasp: str) -> str:
    if not owasp:
        return "General security"
    if "—" in owasp:
        return owasp.split("—", 1)[1].strip()
    return owasp


def generate_template_report(target_url: str, findings: list[Finding]) -> tuple[str, str, str]:
    """Fallback report when no AI API key is configured."""
    counts = _count_by_risk(findings)
    grade = risk_grade(counts["Critical"], counts["High"], counts["Medium"])

    executive = (
        f"We checked {target_url} and gave it a safety score of **{grade}** "
        f"(A is best, F needs urgent attention). "
        f"We found {len(findings)} issue(s): "
        f"{counts['High']} serious, {counts['Medium']} moderate, {counts['Low']} minor, "
        f"and {counts['Informational']} low-priority notes. "
    )
    if counts["High"] or counts["Critical"]:
        executive += (
            "Please fix the serious issues first — they could let someone steal data "
            "or break into your site."
        )
    else:
        executive += (
            "We did not find serious break-in risks, but improving your site settings "
            "and security headers is still recommended."
        )

    lines = [
        f"# ShieldScan Security Report\n",
        f"**Target:** {target_url}\n",
        f"**Risk Grade:** {grade}\n",
        f"**Total Findings:** {len(findings)}\n",
        "## Executive Summary\n",
        executive,
        "\n## Prioritised Findings\n",
    ]

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.risk, 5))

    for i, f in enumerate(sorted_findings[:20], 1):
        lines.append(f"### {i}. [{f.risk}] {f.name}\n")
        lines.append(f"- **URL:** {f.url}\n")
        if f.parameter:
            lines.append(f"- **Parameter:** {f.parameter}\n")
        lines.append(f"- **Category:** {friendly_category_label(f.owasp_category)}\n")
        lines.append(f"- **What it means:** {f.description or 'Something on your site could be safer.'}\n")
        lines.append(f"- **How to fix:** {f.solution or 'Ask your web developer or hosting provider to review this.'}\n")
        if f.evidence:
            lines.append(f"- **Evidence:** `{f.evidence[:200]}`\n")
        lines.append("\n")

    lines.append("## Tips for small business owners\n")
    lines.append(
        "1. Fix serious problems within 48 hours if you handle customer data.\n"
        "2. Ask your developer to add basic security headers (your host can often help).\n"
        "3. Keep WordPress, plugins, and any shop software up to date.\n"
        "4. Run another scan after changes to confirm fixes worked.\n"
        "5. Before launching payments or personal data, consider a professional security review.\n"
    )

    full_report = "".join(lines)
    return executive, grade, full_report


async def generate_ai_report(
    settings: Settings,
    target_url: str,
    findings: list[Finding],
) -> tuple[str, str, str]:
    if not settings.anthropic_api_key:
        return generate_template_report(target_url, findings)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        findings_payload = [f.model_dump() for f in findings]
        counts = _count_by_risk(findings)
        grade = risk_grade(counts["Critical"], counts["High"], counts["Medium"])

        prompt = f"""You are a friendly cybersecurity advisor writing a website security report for a small business owner (e.g. a shop, salon, or restaurant) with no IT background.

Target URL: {target_url}
Safety score (pre-calculated, A=best, F=urgent): {grade}
Findings (JSON): {json.dumps(findings_payload[:30], indent=2)}

Write a report with these sections:
1. EXECUTIVE SUMMARY (3-4 short sentences, everyday language, no acronyms unless you explain them)
2. TOP PRIORITIES (numbered list, most urgent first, max 5 items — say what to fix and why it matters to the business)
3. DETAILED FINDINGS (for each finding: plain explanation, business impact, simple fix steps)
4. NEXT STEPS (short checklist the owner can give their developer or host)

Rules:
- Only discuss findings in the JSON. Do NOT invent problems.
- Write like you're explaining to a smart non-technical person.
- Give practical fixes, not vague advice.
- Mention actual page URLs from the data."""

        message = client.messages.create(
            model=settings.ai_model,
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        full_report = message.content[0].text
        executive = full_report.split("TOP PRIORITIES")[0].replace("EXECUTIVE SUMMARY", "").strip()
        if len(executive) > 600:
            executive = executive[:600] + "..."
        return executive, grade, full_report
    except Exception as exc:
        logger.warning("AI report failed, using template: %s", exc)
        return generate_template_report(target_url, findings)
