"""
FORENSTIX — VirusTotal Integration
Lookup file hashes against VirusTotal's database for known threat intelligence.
"""

import os
import requests

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
VT_API_URL = 'https://www.virustotal.com/api/v3/files'


def lookup_hash(file_hash):
    """Query VirusTotal for a file hash (MD5, SHA-1, or SHA-256)."""
    if not VT_API_KEY:
        return {
            'status': 'no_api_key',
            'message': 'VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY to enable threat lookups.',
            'hash_queried': file_hash
        }

    try:
        response = requests.get(
            f'{VT_API_URL}/{file_hash}',
            headers={'x-apikey': VT_API_KEY},
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            results = attrs.get('last_analysis_results', {})

            total_engines = sum(stats.values())
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)

            # Get top detections
            detections = []
            for engine, result in results.items():
                if result.get('category') in ('malicious', 'suspicious'):
                    detections.append({
                        'engine': engine,
                        'category': result.get('category'),
                        'result': result.get('result', 'Unknown')
                    })

            # Sort by category (malicious first)
            detections.sort(key=lambda x: 0 if x['category'] == 'malicious' else 1)

            # Determine threat level
            detection_ratio = (malicious + suspicious) / max(total_engines, 1)
            if detection_ratio > 0.5:
                threat_level = 'MALICIOUS'
            elif detection_ratio > 0.2:
                threat_level = 'SUSPICIOUS'
            elif detection_ratio > 0:
                threat_level = 'LOW_RISK'
            else:
                threat_level = 'CLEAN'

            return {
                'status': 'found',
                'hash_queried': file_hash,
                'threat_level': threat_level,
                'stats': {
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': undetected,
                    'harmless': harmless,
                    'total_engines': total_engines
                },
                'detection_ratio': f'{malicious + suspicious}/{total_engines}',
                'detections': detections[:15],  # Top 15 detections
                'file_info': {
                    'type_description': attrs.get('type_description', 'Unknown'),
                    'type_tag': attrs.get('type_tag', ''),
                    'size': attrs.get('size', 0),
                    'first_seen': attrs.get('first_submission_date', None),
                    'last_seen': attrs.get('last_submission_date', None),
                    'times_submitted': attrs.get('times_submitted', 0),
                    'reputation': attrs.get('reputation', 0),
                    'names': attrs.get('names', [])[:5],
                    'tags': attrs.get('tags', [])[:10],
                },
                'permalink': f'https://www.virustotal.com/gui/file/{file_hash}'
            }

        elif response.status_code == 404:
            return {
                'status': 'not_found',
                'hash_queried': file_hash,
                'threat_level': 'UNKNOWN',
                'message': 'This file hash has never been submitted to VirusTotal. This does not mean the file is safe — it simply has not been analyzed before.'
            }

        elif response.status_code == 429:
            return {
                'status': 'rate_limited',
                'hash_queried': file_hash,
                'message': 'VirusTotal API rate limit reached. Free tier allows 4 requests/minute. Try again shortly.'
            }

        else:
            return {
                'status': 'error',
                'hash_queried': file_hash,
                'message': f'VirusTotal returned HTTP {response.status_code}'
            }

    except requests.exceptions.Timeout:
        return {
            'status': 'error',
            'hash_queried': file_hash,
            'message': 'VirusTotal request timed out. Check your connection and try again.'
        }
    except Exception as e:
        return {
            'status': 'error',
            'hash_queried': file_hash,
            'message': f'VirusTotal lookup failed: {str(e)}'
        }
