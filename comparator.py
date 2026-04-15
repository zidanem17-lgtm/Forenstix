"""
FORENSTIX — File Comparison Engine
Compares forensic analysis results across 2+ files to identify similarities,
differences, and relationships between evidence files.
"""

import difflib
from collections import defaultdict


def compare_files(analyses):
    """
    Compare multiple file analyses and produce a comparison report.
    
    Args:
        analyses: list of analysis result dicts from analyzer.analyze_file()
    
    Returns:
        Comparison report dict with findings.
    """
    if len(analyses) < 2:
        return {'error': 'Need at least 2 files to compare'}

    comparison = {
        'file_count': len(analyses),
        'files': [],
        'hash_matches': [],
        'type_analysis': {},
        'entropy_comparison': [],
        'metadata_comparison': {},
        'shared_artifacts': {},
        'anomaly_summary': [],
        'risk_comparison': [],
        'relationship_assessment': '',
        'findings': []
    }

    # ─── File summaries ───
    for a in analyses:
        comparison['files'].append({
            'filename': a['metadata']['filename'],
            'size': a['metadata']['file_size_human'],
            'type': a['file_type']['detected_type'],
            'risk_score': a['risk_score']['score'],
            'risk_label': a['risk_score']['label'],
            'sha256': a['hashes']['sha256']
        })

    # ─── 1. Hash matching — are any files identical? ───
    hash_groups = defaultdict(list)
    for a in analyses:
        hash_groups[a['hashes']['sha256']].append(a['metadata']['filename'])

    for sha256, filenames in hash_groups.items():
        if len(filenames) > 1:
            comparison['hash_matches'].append({
                'sha256': sha256,
                'matching_files': filenames,
                'finding': f'{len(filenames)} files are byte-for-byte identical (same SHA-256 hash)'
            })
            comparison['findings'].append({
                'severity': 'warning',
                'title': 'Identical Files Detected',
                'detail': f'Files {", ".join(filenames)} share the same SHA-256 hash ({sha256[:16]}...), meaning they are exact duplicates.'
            })

    # ─── 2. File type analysis ───
    type_groups = defaultdict(list)
    for a in analyses:
        type_groups[a['file_type']['detected_type']].append(a['metadata']['filename'])

    comparison['type_analysis'] = {
        'all_same_type': len(type_groups) == 1,
        'types_found': dict(type_groups),
        'type_count': len(type_groups)
    }

    if len(type_groups) == 1:
        comparison['findings'].append({
            'severity': 'info',
            'title': 'Uniform File Types',
            'detail': f'All {len(analyses)} files are the same type: {list(type_groups.keys())[0]}.'
        })

    # Check for type mismatches across files (e.g., all claim to be images but one is an exe)
    for a in analyses:
        if a['file_type']['detected_type'] in ('Windows Executable (PE)', 'ELF Executable (Linux)'):
            ext = a['metadata']['extension']
            if ext not in ('.exe', '.dll', '.sys', '.elf', ''):
                comparison['findings'].append({
                    'severity': 'critical',
                    'title': f'Disguised Executable: {a["metadata"]["filename"]}',
                    'detail': f'This file uses a "{ext}" extension but is actually a {a["file_type"]["detected_type"]}.'
                })

    # ─── 3. Entropy comparison ───
    entropies = []
    for a in analyses:
        entropies.append({
            'filename': a['metadata']['filename'],
            'entropy': a['entropy']['entropy'],
            'assessment': a['entropy']['assessment']
        })
    entropies.sort(key=lambda x: x['entropy'], reverse=True)
    comparison['entropy_comparison'] = entropies

    # Flag entropy outliers
    entropy_values = [e['entropy'] for e in entropies]
    if entropy_values:
        avg_entropy = sum(entropy_values) / len(entropy_values)
        for e in entropies:
            if abs(e['entropy'] - avg_entropy) > 2.0:
                comparison['findings'].append({
                    'severity': 'warning',
                    'title': f'Entropy Outlier: {e["filename"]}',
                    'detail': f'Entropy of {e["entropy"]:.4f} is significantly different from the group average of {avg_entropy:.4f}. This file may be encrypted, packed, or fundamentally different in nature.'
                })

    # ─── 4. Metadata comparison ───
    comparison['metadata_comparison'] = {
        'size_range': {
            'smallest': min(analyses, key=lambda a: a['metadata']['file_size_bytes'])['metadata']['filename'],
            'smallest_size': min(a['metadata']['file_size_human'] for a in analyses),
            'largest': max(analyses, key=lambda a: a['metadata']['file_size_bytes'])['metadata']['filename'],
            'largest_size': max(a['metadata']['file_size_human'] for a in analyses),
        },
        'timestamp_range': {
            'earliest_modified': min(a['metadata']['modified'] for a in analyses),
            'latest_modified': max(a['metadata']['modified'] for a in analyses),
        }
    }

    # ─── 5. Shared embedded artifacts ───
    all_urls = defaultdict(list)
    all_emails = defaultdict(list)
    all_ips = defaultdict(list)

    for a in analyses:
        ns = a['metadata'].get('notable_strings', {})
        fname = a['metadata']['filename']
        for url in (ns or {}).get('urls', []):
            all_urls[url].append(fname)
        for email in (ns or {}).get('emails', []):
            all_emails[email].append(fname)
        for ip in (ns or {}).get('ip_addresses', []):
            all_ips[ip].append(fname)

    shared_urls = {k: v for k, v in all_urls.items() if len(v) > 1}
    shared_emails = {k: v for k, v in all_emails.items() if len(v) > 1}
    shared_ips = {k: v for k, v in all_ips.items() if len(v) > 1}

    comparison['shared_artifacts'] = {
        'shared_urls': shared_urls,
        'shared_emails': shared_emails,
        'shared_ips': shared_ips,
        'has_shared': bool(shared_urls or shared_emails or shared_ips)
    }

    if shared_urls:
        comparison['findings'].append({
            'severity': 'warning',
            'title': 'Shared URLs Across Files',
            'detail': f'{len(shared_urls)} URL(s) appear in multiple files, suggesting a common origin or campaign.'
        })
    if shared_emails:
        comparison['findings'].append({
            'severity': 'warning',
            'title': 'Shared Email Addresses',
            'detail': f'{len(shared_emails)} email address(es) appear across multiple files.'
        })
    if shared_ips:
        comparison['findings'].append({
            'severity': 'warning',
            'title': 'Shared IP Addresses',
            'detail': f'{len(shared_ips)} IP address(es) appear in multiple files, indicating possible C2 infrastructure or common source.'
        })

    # ─── 6. Anomaly summary ───
    total_anomalies = 0
    critical_files = []
    for a in analyses:
        count = len(a.get('anomalies', []))
        total_anomalies += count
        if a['risk_score']['label'] in ('CRITICAL', 'SUSPICIOUS'):
            critical_files.append(a['metadata']['filename'])

    comparison['anomaly_summary'] = {
        'total_anomalies': total_anomalies,
        'critical_files': critical_files,
        'clean_files': [a['metadata']['filename'] for a in analyses if a['risk_score']['label'] == 'CLEAN']
    }

    # ─── 7. Risk comparison ───
    comparison['risk_comparison'] = sorted(
        [{'filename': a['metadata']['filename'],
          'score': a['risk_score']['score'],
          'label': a['risk_score']['label']}
         for a in analyses],
        key=lambda x: x['score'],
        reverse=True
    )

    # ─── 8. Relationship assessment ───
    if comparison['hash_matches']:
        comparison['relationship_assessment'] = 'DUPLICATE_FILES'
    elif comparison['shared_artifacts']['has_shared']:
        comparison['relationship_assessment'] = 'RELATED_FILES'
    elif len(type_groups) == 1:
        comparison['relationship_assessment'] = 'SAME_TYPE'
    else:
        comparison['relationship_assessment'] = 'UNRELATED'

    return comparison
