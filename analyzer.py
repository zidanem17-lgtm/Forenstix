"""
FORENSTIX — Core Forensic Analysis Engine
Handles: hashing, magic byte detection, metadata extraction, entropy analysis, anomaly flagging.
"""

import hashlib
import math
import os
import struct
import json
import datetime
from collections import Counter

# ─── Magic byte signatures for file type detection ───
MAGIC_SIGNATURES = {
    b'\xFF\xD8\xFF': ('JPEG Image', '.jpg'),
    b'\x89PNG\r\n\x1a\n': ('PNG Image', '.png'),
    b'GIF87a': ('GIF Image (87a)', '.gif'),
    b'GIF89a': ('GIF Image (89a)', '.gif'),
    b'%PDF': ('PDF Document', '.pdf'),
    b'PK\x03\x04': ('ZIP Archive / Office Document', '.zip'),
    b'PK\x05\x06': ('ZIP Archive (empty)', '.zip'),
    b'Rar!\x1a\x07': ('RAR Archive', '.rar'),
    b'\x1f\x8b': ('GZIP Archive', '.gz'),
    b'BZ': ('BZIP2 Archive', '.bz2'),
    b'\x7fELF': ('ELF Executable (Linux)', '.elf'),
    b'MZ': ('Windows Executable (PE)', '.exe'),
    b'\xCA\xFE\xBA\xBE': ('Java Class / Mach-O Fat Binary', '.class'),
    b'\xFE\xED\xFA': ('Mach-O Executable (macOS)', '.macho'),
    b'\xCF\xFA\xED\xFE': ('Mach-O Executable (macOS, 64-bit)', '.macho'),
    b'SQLite format 3': ('SQLite Database', '.sqlite'),
    b'\x00\x00\x01\x00': ('ICO Icon', '.ico'),
    b'RIFF': ('RIFF Container (AVI/WAV)', '.riff'),
    b'\x00\x00\x00\x1c\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x00\x00\x00\x18\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x00\x00\x00\x20\x66\x74\x79\x70': ('MP4 Video', '.mp4'),
    b'\x49\x44\x33': ('MP3 Audio (ID3)', '.mp3'),
    b'\xFF\xFB': ('MP3 Audio', '.mp3'),
    b'\xFF\xF3': ('MP3 Audio', '.mp3'),
    b'OggS': ('OGG Audio', '.ogg'),
    b'fLaC': ('FLAC Audio', '.flac'),
    b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('MS Office Open XML', '.docx'),
    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('MS Office Legacy (DOC/XLS/PPT)', '.doc'),
    b'<!DOCTYPE html': ('HTML Document', '.html'),
    b'<html': ('HTML Document', '.html'),
    b'<?xml': ('XML Document', '.xml'),
    b'\x37\x7A\xBC\xAF\x27\x1C': ('7-Zip Archive', '.7z'),
    b'\x04\x22\x4D\x18': ('LZ4 Archive', '.lz4'),
    b'\x28\xB5\x2F\xFD': ('Zstandard Archive', '.zst'),
}

# Extension-to-expected-type mapping for mismatch detection
EXTENSION_TYPE_MAP = {
    '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
    '.bmp': 'image', '.ico': 'image', '.webp': 'image', '.svg': 'image',
    '.pdf': 'document', '.doc': 'document', '.docx': 'document',
    '.xls': 'spreadsheet', '.xlsx': 'spreadsheet',
    '.ppt': 'presentation', '.pptx': 'presentation',
    '.exe': 'executable', '.dll': 'executable', '.sys': 'executable',
    '.bat': 'script', '.cmd': 'script', '.ps1': 'script', '.sh': 'script',
    '.py': 'script', '.js': 'script', '.vbs': 'script',
    '.zip': 'archive', '.rar': 'archive', '.7z': 'archive',
    '.gz': 'archive', '.tar': 'archive', '.bz2': 'archive',
    '.mp3': 'audio', '.wav': 'audio', '.flac': 'audio', '.ogg': 'audio',
    '.mp4': 'video', '.avi': 'video', '.mkv': 'video', '.mov': 'video',
    '.txt': 'text', '.csv': 'text', '.log': 'text', '.json': 'text',
    '.html': 'web', '.htm': 'web', '.xml': 'web', '.css': 'web',
}

DANGEROUS_REAL_TYPES = {'Windows Executable (PE)', 'ELF Executable (Linux)',
                        'Mach-O Executable (macOS)', 'Mach-O Executable (macOS, 64-bit)'}


def compute_hashes(filepath):
    """Compute MD5, SHA-1, and SHA-256 hashes."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest()
    }


def detect_file_type(filepath):
    """Detect actual file type using magic bytes."""
    with open(filepath, 'rb') as f:
        header = f.read(32)

    for signature, (file_type, ext) in sorted(MAGIC_SIGNATURES.items(), key=lambda x: -len(x[0])):
        if header[:len(signature)] == signature:
            return {
                'detected_type': file_type,
                'detected_extension': ext,
                'magic_bytes': header[:len(signature)].hex(),
                'match_confidence': 'high'
            }

    # Check if it's plain text
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            f.read(1024)
        return {
            'detected_type': 'Plain Text / Script',
            'detected_extension': '.txt',
            'magic_bytes': header[:8].hex(),
            'match_confidence': 'medium'
        }
    except (UnicodeDecodeError, ValueError):
        return {
            'detected_type': 'Unknown Binary',
            'detected_extension': 'unknown',
            'magic_bytes': header[:8].hex(),
            'match_confidence': 'low'
        }


def calculate_entropy(filepath):
    """Calculate Shannon entropy of file contents. Higher = more random/encrypted."""
    with open(filepath, 'rb') as f:
        data = f.read()

    if not data:
        return {'entropy': 0.0, 'assessment': 'Empty file', 'risk_level': 'info'}

    byte_counts = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in byte_counts.values())

    if entropy > 7.9:
        assessment = 'Very high entropy — likely encrypted, compressed, or packed'
        risk = 'high'
    elif entropy > 7.0:
        assessment = 'High entropy — possibly compressed or obfuscated'
        risk = 'medium'
    elif entropy > 5.0:
        assessment = 'Moderate entropy — typical for compiled binaries or mixed content'
        risk = 'low'
    elif entropy > 3.0:
        assessment = 'Low-moderate entropy — typical for text or structured data'
        risk = 'info'
    else:
        assessment = 'Low entropy — highly structured or repetitive data'
        risk = 'info'

    return {
        'entropy': round(entropy, 4),
        'max_possible': 8.0,
        'assessment': assessment,
        'risk_level': risk
    }


def extract_metadata(filepath):
    """Extract filesystem and embedded metadata."""
    stat = os.stat(filepath)
    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename)

    meta = {
        'filename': filename,
        'extension': ext.lower(),
        'file_size_bytes': stat.st_size,
        'file_size_human': _human_size(stat.st_size),
        'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
    }

    # Try to extract EXIF from images
    exif_data = _extract_exif(filepath, ext.lower())
    if exif_data:
        meta['exif'] = exif_data

    # Try to extract PDF metadata
    if ext.lower() == '.pdf':
        pdf_meta = _extract_pdf_metadata(filepath)
        if pdf_meta:
            meta['pdf_metadata'] = pdf_meta

    # Check for embedded strings of interest
    strings_of_interest = _extract_interesting_strings(filepath)
    if strings_of_interest:
        meta['notable_strings'] = strings_of_interest

    return meta


def check_anomalies(filepath, file_type_info, metadata, entropy_info):
    """Flag suspicious anomalies."""
    anomalies = []
    ext = metadata.get('extension', '').lower()
    detected = file_type_info.get('detected_type', '')

    # 1. Extension mismatch
    if ext and ext != file_type_info.get('detected_extension', ''):
        is_dangerous = detected in DANGEROUS_REAL_TYPES
        anomalies.append({
            'type': 'EXTENSION_MISMATCH',
            'severity': 'critical' if is_dangerous else 'warning',
            'title': 'File Extension Mismatch',
            'detail': f'File claims to be "{ext}" but magic bytes indicate "{detected}".',
            'recommendation': 'Do not open this file. The extension has been changed to disguise its true type.' if is_dangerous else 'Verify the file origin. The extension does not match the actual content.'
        })

    # 2. Hidden executable
    if detected in DANGEROUS_REAL_TYPES and ext not in ('.exe', '.dll', '.sys', '.elf', '.macho'):
        anomalies.append({
            'type': 'HIDDEN_EXECUTABLE',
            'severity': 'critical',
            'title': 'Hidden Executable Detected',
            'detail': f'This file is actually a "{detected}" disguised with a "{ext}" extension.',
            'recommendation': 'DANGER: This file is a disguised executable. Quarantine immediately and investigate the source.'
        })

    # 3. High entropy
    if entropy_info.get('entropy', 0) > 7.9:
        anomalies.append({
            'type': 'HIGH_ENTROPY',
            'severity': 'warning',
            'title': 'Extremely High Entropy',
            'detail': f'Entropy of {entropy_info["entropy"]} suggests encryption, packing, or steganography.',
            'recommendation': 'Investigate whether this file has been encrypted or packed to evade detection.'
        })

    # 4. Double extension trick (e.g., document.pdf.exe)
    basename = os.path.basename(filepath)
    parts = basename.split('.')
    if len(parts) > 2:
        anomalies.append({
            'type': 'DOUBLE_EXTENSION',
            'severity': 'warning',
            'title': 'Multiple File Extensions',
            'detail': f'File has multiple extensions: {".".join(parts[1:])}. This is a common social engineering tactic.',
            'recommendation': 'Multiple extensions can be used to trick users. Verify the file type using magic bytes above.'
        })

    # 5. Zero-byte file
    if metadata.get('file_size_bytes', 0) == 0:
        anomalies.append({
            'type': 'ZERO_BYTE',
            'severity': 'info',
            'title': 'Zero-Byte File',
            'detail': 'This file contains no data.',
            'recommendation': 'Empty files may indicate failed transfers, evidence tampering, or placeholder files.'
        })

    # 6. Timestamp anomalies (created after modified)
    try:
        created = datetime.datetime.fromisoformat(metadata.get('created', ''))
        modified = datetime.datetime.fromisoformat(metadata.get('modified', ''))
        if created > modified:
            anomalies.append({
                'type': 'TIMESTAMP_ANOMALY',
                'severity': 'warning',
                'title': 'Timestamp Inconsistency',
                'detail': 'File creation date is later than modification date, suggesting timestamp manipulation.',
                'recommendation': 'Timestamps may have been altered. Cross-reference with filesystem journal or log files.'
            })
    except (ValueError, TypeError):
        pass

    return anomalies


def analyze_file(filepath):
    """Run full forensic analysis on a file."""
    results = {
        'analysis_timestamp': datetime.datetime.now().isoformat(),
        'tool': 'FORENSTIX v1.0',
    }

    results['hashes'] = compute_hashes(filepath)
    results['file_type'] = detect_file_type(filepath)
    results['entropy'] = calculate_entropy(filepath)
    results['metadata'] = extract_metadata(filepath)
    results['anomalies'] = check_anomalies(
        filepath,
        results['file_type'],
        results['metadata'],
        results['entropy']
    )

    # Overall risk score
    results['risk_score'] = _calculate_risk_score(results)

    return results


# ─── Helper Functions ───

def _human_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def _extract_exif(filepath, ext):
    """Basic EXIF extraction for JPEG files."""
    if ext not in ('.jpg', '.jpeg'):
        return None

    exif = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # Look for EXIF header
        if b'Exif' not in data[:100]:
            return None

        # Extract readable ASCII strings from EXIF region
        exif_region = data[:min(65536, len(data))]
        # Look for common EXIF tags as ASCII
        for tag_name in [b'Make', b'Model', b'Software', b'DateTime', b'Artist',
                         b'Copyright', b'ImageDescription']:
            idx = exif_region.find(tag_name)
            if idx != -1:
                # Try to read the value after the tag
                value_start = idx + len(tag_name) + 1
                value_end = exif_region.find(b'\x00', value_start)
                if value_end != -1 and value_end - value_start < 200:
                    try:
                        val = exif_region[value_start:value_end].decode('ascii', errors='ignore').strip()
                        if val and val.isprintable():
                            exif[tag_name.decode()] = val
                    except Exception:
                        pass

        # Check for GPS data presence
        if b'GPS' in exif_region:
            exif['gps_data_present'] = True

    except Exception:
        pass

    return exif if exif else None


def _extract_pdf_metadata(filepath):
    """Basic PDF metadata extraction."""
    meta = {}
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8192).decode('latin-1', errors='ignore')

        for field in ['Title', 'Author', 'Creator', 'Producer', 'CreationDate', 'ModDate']:
            marker = f'/{field}'
            idx = data.find(marker)
            if idx != -1:
                # Extract the value (between parentheses or after the key)
                paren_start = data.find('(', idx)
                paren_end = data.find(')', paren_start + 1) if paren_start != -1 else -1
                if paren_start != -1 and paren_end != -1 and paren_end - paren_start < 300:
                    val = data[paren_start + 1:paren_end].strip()
                    if val:
                        meta[field] = val
    except Exception:
        pass

    return meta if meta else None


def _extract_interesting_strings(filepath):
    """Extract potentially interesting strings (URLs, emails, IPs)."""
    import re
    interesting = {'urls': [], 'emails': [], 'ip_addresses': []}

    try:
        with open(filepath, 'rb') as f:
            # Read first 1MB only
            raw = f.read(1048576)

        text = raw.decode('ascii', errors='ignore')

        # URLs
        urls = re.findall(r'https?://[^\s<>"\']+', text)
        interesting['urls'] = list(set(urls))[:10]

        # Emails
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        interesting['emails'] = list(set(emails))[:10]

        # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        ips = [ip for ip in ips if all(0 <= int(p) <= 255 for p in ip.split('.'))]
        interesting['ip_addresses'] = list(set(ips))[:10]

    except Exception:
        pass

    # Only return if we found something
    return {k: v for k, v in interesting.items() if v} or None


def _calculate_risk_score(results):
    """Calculate overall risk score 0-100."""
    score = 0

    # Anomaly-based scoring
    for anomaly in results.get('anomalies', []):
        if anomaly['severity'] == 'critical':
            score += 35
        elif anomaly['severity'] == 'warning':
            score += 15
        elif anomaly['severity'] == 'info':
            score += 5

    # Entropy-based scoring
    entropy = results.get('entropy', {}).get('entropy', 0)
    if entropy > 7.9:
        score += 15
    elif entropy > 7.0:
        score += 8

    # Executable type scoring
    detected = results.get('file_type', {}).get('detected_type', '')
    if detected in DANGEROUS_REAL_TYPES:
        score += 10

    score = min(score, 100)

    risk_label = 'CLEAN'
    if score >= 70:
        risk_label = 'CRITICAL'
    elif score >= 40:
        risk_label = 'SUSPICIOUS'
    elif score >= 15:
        risk_label = 'CAUTION'

    return {'score': score, 'label': risk_label}
