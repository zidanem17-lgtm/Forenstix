# FORENSTIX

Digital forensic file triage web application built with Flask.

## Features

- Single-file forensic triage
- Batch analysis (up to 20 files per request)
- Multi-file forensic comparison (2 to 10 files)
- Hashing (MD5, SHA-1, SHA-256)
- Magic-byte file type detection
- Entropy analysis and anomaly scoring
- Metadata extraction (filesystem + basic EXIF/PDF fields)
- Embedded IOC-style string extraction (URLs, emails, IPs)
- Optional VirusTotal hash lookup
- Humanized markdown report generation
- PDF export for analysis and comparison reports

## Project Structure

- `/app.py` — Flask routes and API endpoints
- `/analyzer.py` — core forensic analysis engine
- `/comparator.py` — cross-file comparison logic
- `/report_generator.py` — narrative report generation (Anthropic + fallback)
- `/virustotal.py` — VirusTotal API integration
- `/templates/index.html` — web UI

## Requirements

- Python 3.10+ recommended
- Dependencies in `requirements.txt`

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Locally

```bash
python app.py
```

App starts on `http://localhost:5000` by default.

## Production Run

The repo includes a `Procfile`:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

## Environment Variables

- `ANTHROPIC_API_KEY` (optional): enables AI-generated humanized reports
- `VIRUSTOTAL_API_KEY` (optional): enables VirusTotal hash reputation lookups
- `PORT` (optional): server port (default: `5000`)

If keys are not configured:
- report generation falls back to built-in local narrative output
- VirusTotal endpoint returns a `no_api_key` status

## API Endpoints

- `GET /` — web interface
- `POST /analyze` — analyze one uploaded file (`file`)
- `POST /analyze-batch` — analyze multiple uploaded files (`files`)
- `POST /compare` — compare multiple uploaded files (`files`)
- `GET /virustotal/<file_hash>` — hash lookup (MD5/SHA-1/SHA-256)
- `POST /export-pdf` — export report HTML payload as PDF

## Analysis Notes

FORENSTIX computes a risk score (`0-100`) and labels files as:
- `CLEAN`
- `CAUTION`
- `SUSPICIOUS`
- `CRITICAL`

Common anomaly checks include:
- extension mismatch
- hidden/disguised executable
- very high entropy
- multiple extensions
- zero-byte files
- timestamp inconsistencies

## Upload Limits (Server-Side)

- Max request size: 500 MB
- Batch analysis: max 20 files
- File comparison: max 10 files (minimum 2)

## Disclaimer

This tool supports triage and investigation workflows. It is not a standalone malware verdict engine and should be used alongside established forensic and incident response procedures.
