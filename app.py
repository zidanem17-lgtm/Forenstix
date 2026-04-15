"""
FORENSTIX — Digital Forensic File Triage Tool
Flask web application with batch analysis, VirusTotal integration, and file comparison.
"""

import os
import json
import datetime
import tempfile
import markdown
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from analyzer import analyze_file
from report_generator import generate_humanized_report
from virustotal import lookup_hash
from comparator import compare_files

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB total for batch
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Single file analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(filepath)
        results = analyze_file(filepath)
        report_markdown = generate_humanized_report(results)
        report_html = markdown.markdown(report_markdown, extensions=['tables', 'fenced_code'])

        return jsonify({
            'results': results,
            'report_markdown': report_markdown,
            'report_html': report_html
        })
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/analyze-batch', methods=['POST'])
def analyze_batch():
    """Batch analysis of multiple files."""
    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files uploaded'}), 400

    if len(files) > 20:
        return jsonify({'error': 'Maximum 20 files per batch'}), 400

    results_list = []
    saved_paths = []

    try:
        for file in files:
            if file.filename == '':
                continue
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'{len(saved_paths)}_{filename}')
            file.save(filepath)
            saved_paths.append(filepath)

            try:
                analysis = analyze_file(filepath)
                report_md = generate_humanized_report(analysis)
                report_html = markdown.markdown(report_md, extensions=['tables', 'fenced_code'])

                results_list.append({
                    'results': analysis,
                    'report_markdown': report_md,
                    'report_html': report_html,
                    'status': 'success'
                })
            except Exception as e:
                results_list.append({
                    'results': {'metadata': {'filename': filename}},
                    'error': str(e),
                    'status': 'error'
                })

        return jsonify({
            'batch_results': results_list,
            'total_files': len(results_list),
            'successful': sum(1 for r in results_list if r['status'] == 'success'),
            'failed': sum(1 for r in results_list if r['status'] == 'error')
        })

    except Exception as e:
        return jsonify({'error': f'Batch analysis failed: {str(e)}'}), 500
    finally:
        for path in saved_paths:
            if os.path.exists(path):
                os.remove(path)


@app.route('/virustotal/<file_hash>', methods=['GET'])
def virustotal_lookup(file_hash):
    """Lookup a file hash on VirusTotal."""
    if not file_hash or len(file_hash) not in (32, 40, 64):
        return jsonify({'error': 'Invalid hash. Provide MD5 (32), SHA-1 (40), or SHA-256 (64).'}), 400

    result = lookup_hash(file_hash)
    return jsonify(result)


@app.route('/compare', methods=['POST'])
def compare():
    """Compare 2+ files forensically."""
    files = request.files.getlist('files')
    if not files or len([f for f in files if f.filename != '']) < 2:
        return jsonify({'error': 'Need at least 2 files for comparison'}), 400

    if len(files) > 10:
        return jsonify({'error': 'Maximum 10 files for comparison'}), 400

    analyses = []
    saved_paths = []

    try:
        for file in files:
            if file.filename == '':
                continue
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f'cmp_{len(saved_paths)}_{filename}')
            file.save(filepath)
            saved_paths.append(filepath)
            analyses.append(analyze_file(filepath))

        comparison = compare_files(analyses)
        narrative = _generate_comparison_narrative(comparison)
        narrative_html = markdown.markdown(narrative, extensions=['tables', 'fenced_code'])

        return jsonify({
            'comparison': comparison,
            'individual_analyses': analyses,
            'narrative_html': narrative_html
        })

    except Exception as e:
        return jsonify({'error': f'Comparison failed: {str(e)}'}), 500
    finally:
        for path in saved_paths:
            if os.path.exists(path):
                os.remove(path)


@app.route('/export-pdf', methods=['POST'])
def export_pdf():
    """Export forensic report as PDF."""
    try:
        data = request.get_json()
        report_html = data.get('report_html', '')
        results = data.get('results', {})
        filename = results.get('metadata', {}).get('filename', 'batch_report')
        report_title = data.get('title', 'Digital Forensic File Triage Report')

        pdf_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
    @page {{ margin: 1in; }}
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 11pt;
           line-height: 1.6; color: #1a1a2e; max-width: 7.5in; margin: 0 auto; }}
    .header {{ border-bottom: 3px solid #0f3460; padding-bottom: 15px; margin-bottom: 25px; }}
    .header h1 {{ color: #0f3460; font-size: 22pt; margin: 0; letter-spacing: 3px; }}
    .header .sub {{ color: #16213e; font-size: 10pt; margin-top: 5px; }}
    .header .meta {{ color: #666; font-size: 9pt; margin-top: 8px; }}
    h2 {{ color: #0f3460; font-size: 14pt; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 25px; }}
    code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px;
           font-family: Consolas, monospace; font-size: 9pt; word-break: break-all; }}
    strong {{ color: #0f3460; }}
    .footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #ddd;
              font-size: 8pt; color: #999; text-align: center; }}
</style></head>
<body>
    <div class="header">
        <h1>FORENSTIX</h1>
        <div class="sub">{report_title}</div>
        <div class="meta">File: {filename} | Analyzed: {datetime.datetime.now().strftime('%B %d, %Y at %I:%M %p')} | v1.0</div>
    </div>
    {report_html}
    <div class="footer">Generated by FORENSTIX v1.0 — For authorized forensic analysis only.</div>
</body></html>"""

        tmp_html = os.path.join(app.config['UPLOAD_FOLDER'], 'report.html')
        tmp_pdf = os.path.join(app.config['UPLOAD_FOLDER'], 'forenstix_report.pdf')

        with open(tmp_html, 'w') as f:
            f.write(pdf_html)

        try:
            from weasyprint import HTML
            HTML(filename=tmp_html).write_pdf(tmp_pdf)
            return send_file(tmp_pdf, as_attachment=True,
                             download_name=f'FORENSTIX_Report_{filename}.pdf',
                             mimetype='application/pdf')
        except ImportError:
            return send_file(tmp_html, as_attachment=True,
                             download_name=f'FORENSTIX_Report_{filename}.html',
                             mimetype='text/html')

    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


def _generate_comparison_narrative(comparison):
    files = comparison['files']
    filenames = [f['filename'] for f in files]

    report = f"## Comparison Summary\n\nAnalyzed **{len(files)} files** side by side: {', '.join(filenames)}.\n\n"

    rel = comparison.get('relationship_assessment', 'UNRELATED')
    rel_map = {
        'DUPLICATE_FILES': 'Some files in this batch are **byte-for-byte duplicates** — identical SHA-256 hashes.',
        'RELATED_FILES': 'These files appear **related** — they share embedded artifacts suggesting a common origin.',
        'SAME_TYPE': 'All files share the **same type** but no other forensic indicators.',
        'UNRELATED': 'These files appear **forensically unrelated** based on all indicators analyzed.'
    }
    report += rel_map.get(rel, '') + '\n\n'

    report += "## Risk Ranking\n\n"
    for r in comparison['risk_comparison']:
        icon = {'CRITICAL': '🔴', 'SUSPICIOUS': '🟠', 'CAUTION': '🟡', 'CLEAN': '🟢'}.get(r['label'], '⚪')
        report += f"- {icon} **{r['filename']}** — {r['score']}/100 ({r['label']})\n"

    if comparison.get('findings'):
        report += "\n## Key Findings\n\n"
        for f in comparison['findings']:
            icon = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}.get(f['severity'], '⚪')
            report += f"{icon} **{f['title']}:** {f['detail']}\n\n"

    shared = comparison.get('shared_artifacts', {})
    if shared.get('has_shared'):
        report += "## Shared Artifacts\n\n"
        for kind, label in [('shared_urls', 'URLs'), ('shared_emails', 'Emails'), ('shared_ips', 'IPs')]:
            items = shared.get(kind, {})
            if items:
                report += f"**{label} in multiple files:**\n"
                for val, fnames in items.items():
                    report += f"- `{val}` → {', '.join(fnames)}\n"
                report += "\n"

    report += "## Entropy Comparison\n\n"
    for e in comparison['entropy_comparison']:
        report += f"- **{e['filename']}** — {e['entropy']:.4f} ({e['assessment']})\n"

    return report


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
