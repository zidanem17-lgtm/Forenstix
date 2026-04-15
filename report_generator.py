"""
FORENSTIX — Humanized Report Generator
Uses Claude API to transform raw forensic data into natural, analyst-style narratives.
"""

import os
import json
import datetime
import requests

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

SYSTEM_PROMPT = """You are a senior digital forensics analyst writing an evidence triage report. 
Your writing style is:
- Professional but conversational — like a seasoned analyst briefing a colleague
- Clear, direct sentences — no jargon dumping, no filler
- You explain what you found and WHY it matters
- You use natural transitions, not robotic bullet points
- You write like a real human expert — confident, specific, occasionally dry-witted when noting something unusual
- You NEVER use phrases like "it's important to note" or "it should be noted" or "in conclusion"
- You NEVER sound like AI-generated text — no hedging, no over-qualifying, no corporate-speak
- You reference specific data points (hashes, entropy values, timestamps) naturally within sentences

Structure your report with these sections (use markdown headers):
## Executive Summary
A 2-3 sentence overview of what this file is, whether it's suspicious, and the bottom line.

## File Identity
Discuss the hashes, file type detection, and whether the file is what it claims to be.

## Content Analysis  
Cover entropy findings, metadata, and any embedded artifacts (strings, URLs, emails, IPs).

## Anomaly Assessment
Detail any red flags found. If none, say so plainly.

## Analyst Recommendation
What should be done with this file? Be specific and actionable.

Keep the entire report between 300-500 words. Write it in a way that a junior analyst could understand but a senior analyst would respect."""


def generate_humanized_report(analysis_results):
    """Generate a human-style forensic narrative using Claude API."""

    if not ANTHROPIC_API_KEY:
        return _generate_fallback_report(analysis_results)

    # Build the data payload for the AI
    data_summary = json.dumps(analysis_results, indent=2, default=str)

    user_prompt = f"""Here is the raw forensic analysis data for a file. Write a humanized forensic triage report based on this data.

Raw Analysis Data:
{data_summary}

Write the report now. Remember: sound like a real forensic analyst, not an AI."""

    try:
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'Content-Type': 'application/json',
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01'
            },
            json={
                'model': 'claude-sonnet-4-20250514',
                'max_tokens': 1500,
                'system': SYSTEM_PROMPT,
                'messages': [
                    {'role': 'user', 'content': user_prompt}
                ]
            },
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            report_text = ''
            for block in result.get('content', []):
                if block.get('type') == 'text':
                    report_text += block['text']
            return report_text if report_text else _generate_fallback_report(analysis_results)
        else:
            print(f"API Error {response.status_code}: {response.text}")
            return _generate_fallback_report(analysis_results)

    except Exception as e:
        print(f"Report generation error: {e}")
        return _generate_fallback_report(analysis_results)


def _generate_fallback_report(results):
    """Fallback report if API is unavailable — still human-readable."""
    meta = results.get('metadata', {})
    hashes = results.get('hashes', {})
    ft = results.get('file_type', {})
    entropy = results.get('entropy', {})
    anomalies = results.get('anomalies', [])
    risk = results.get('risk_score', {})

    report = f"""## Executive Summary

This report covers the forensic triage of **{meta.get('filename', 'unknown')}**, a {meta.get('file_size_human', 'unknown size')} file analyzed on {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')}. The file received a risk score of **{risk.get('score', 0)}/100 ({risk.get('label', 'UNKNOWN')})**.

## File Identity

The file identifies as **{ft.get('detected_type', 'Unknown')}** based on magic byte analysis (signature: `{ft.get('magic_bytes', 'N/A')}`). The claimed extension is `{meta.get('extension', 'none')}` and the detected extension is `{ft.get('detected_extension', 'unknown')}`.

Integrity hashes for chain-of-custody:
- **MD5:** `{hashes.get('md5', 'N/A')}`
- **SHA-1:** `{hashes.get('sha1', 'N/A')}`
- **SHA-256:** `{hashes.get('sha256', 'N/A')}`

## Content Analysis

Shannon entropy measured at **{entropy.get('entropy', 0)}** out of a maximum 8.0. {entropy.get('assessment', '')}

The file was created on {meta.get('created', 'unknown')} and last modified on {meta.get('modified', 'unknown')}.
"""

    # EXIF data
    if meta.get('exif'):
        report += "\nEmbedded EXIF metadata was recovered:\n"
        for k, v in meta['exif'].items():
            report += f"- **{k}:** {v}\n"

    # Notable strings
    if meta.get('notable_strings'):
        ns = meta['notable_strings']
        if ns.get('urls'):
            report += f"\n**Embedded URLs found:** {', '.join(ns['urls'][:5])}\n"
        if ns.get('emails'):
            report += f"\n**Embedded email addresses:** {', '.join(ns['emails'][:5])}\n"
        if ns.get('ip_addresses'):
            report += f"\n**IP addresses found:** {', '.join(ns['ip_addresses'][:5])}\n"

    # Anomalies
    report += "\n## Anomaly Assessment\n\n"
    if anomalies:
        for a in anomalies:
            severity_icon = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}.get(a['severity'], '⚪')
            report += f"{severity_icon} **{a['title']}** ({a['severity'].upper()})\n"
            report += f"{a['detail']}\n"
            report += f"*Recommendation: {a['recommendation']}*\n\n"
    else:
        report += "No anomalies were detected during this analysis. The file appears to be consistent with its claimed type and shows no signs of tampering or obfuscation.\n"

    # Recommendation
    report += f"\n## Analyst Recommendation\n\n"
    if risk.get('score', 0) >= 70:
        report += "This file should be **quarantined immediately** and not opened on any production system. A deeper forensic examination is warranted, including sandbox detonation and behavioral analysis.\n"
    elif risk.get('score', 0) >= 40:
        report += "This file warrants **further investigation** before being considered safe. Open only in an isolated sandbox environment and verify its origin through independent channels.\n"
    elif risk.get('score', 0) >= 15:
        report += "This file shows minor indicators worth noting but does not appear to pose an immediate threat. Standard precautions apply — verify the source and context before use.\n"
    else:
        report += "This file appears clean and consistent with its claimed type. No immediate action is required beyond standard evidence handling procedures.\n"

    return report
