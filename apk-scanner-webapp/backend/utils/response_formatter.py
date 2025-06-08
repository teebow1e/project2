# utils/response_formatter.py
from datetime import datetime
def format_results_for_frontend(results):
    """Format analysis results for frontend consumption"""

    # Extract data with safe defaults
    manifest = results.get('manifest', {})
    basic_info = results.get('basic_info', {})
    permissions = results.get('permissions', {})
    security = results.get('security', {})

    formatted = {
        'basicInfo': {
            'packageName': manifest.get('package_name', 'Unknown'),
            'appName': manifest.get('app_name', 'Mobile Application'),
            'version': manifest.get('version_name', 'Unknown'),
            'versionCode': manifest.get('version_code', 'Unknown'),
            'minSDK': f"{manifest.get('min_sdk', 'Unknown')}",
            'targetSDK': f"{manifest.get('target_sdk', 'Unknown')}",
            'fileSize': basic_info.get('file_size', 0)
        },

        'technicalInfo': {
            'architecture': determine_architecture(results),
            'signingAlgorithm': get_signing_algorithm(security),
            'compiledDate': datetime.now().strftime('%Y-%m-%d'),
            'debuggable': 'Yes' if security.get('is_debuggable') else 'No',
            'allowBackup': 'Yes' if security.get('allows_backup') else 'No'
        },

        'statistics': {
            'totalPermissions': str(permissions.get('total_permissions', 0)),
            'dangerousPermissions': str(permissions.get('risk_summary', {}).get('high', 0)),
            'activities': str(len(manifest.get('activities', []))),
            'services': str(len(manifest.get('services', []))),
            'receivers': str(len(manifest.get('receivers', [])))
        },

        'permissions': permissions.get('detected_permissions', []),

        'security': {
            'signed': 'Yes' if security.get('is_signed', {}).get('signed') else 'No',
            'debuggable': 'Yes' if security.get('is_debuggable') else 'No',
            'networkSecurity': get_network_security_status(security),
            'antiAnalysis': get_anti_analysis_status(security)
        },

        'risks': {
            'highRisk': f"{permissions.get('risk_summary', {}).get('high', 0)} issues found",
            'mediumRisk': f"{permissions.get('risk_summary', {}).get('medium', 0)} issues found",
            'lowRisk': f"{permissions.get('risk_summary', {}).get('low', 0)} issues found"
        },

        'aiAnalysis': results.get('ai_analysis', {}).get('analysis_summary', 'Analysis not available'),

        'hashes': results.get('hashes', {}),
        'fileStructure': results.get('file_structure', {}),
        'metadata': results.get('metadata', {}),
        'malwareAnalysis': results.get('malware', {}),
        'riskScore': results.get('ai_analysis', {}).get('risk_score', 0)
    }

    return formatted

def determine_architecture(results):
    """Determine app architecture from native libraries"""
    file_structure = results.get('file_structure', {})
    native_libs = file_structure.get('native_libraries', [])

    architectures = set()
    for lib in native_libs:
        lib_path = lib.get('name', '') if isinstance(lib, dict) else lib
        if 'arm64-v8a' in lib_path:
            architectures.add('ARM64')
        elif 'armeabi-v7a' in lib_path:
            architectures.add('ARMv7')
        elif 'x86_64' in lib_path:
            architectures.add('x86_64')
        elif 'x86' in lib_path:
            architectures.add('x86')

    return ', '.join(sorted(architectures)) if architectures else 'Universal'

def get_signing_algorithm(security):
    """Get signing algorithm information"""
    signature_info = security.get('signature_details', {})
    if signature_info.get('valid'):
        algorithm = signature_info.get('algorithm', 'RSA')
        return f"SHA256with{algorithm.upper()}"
    return 'Not Signed'

def get_network_security_status(security):
    """Get network security configuration status"""
    network_config = security.get('network_security_config', {})
    if network_config.get('present'):
        return 'Enhanced'
    return 'Standard'

def get_anti_analysis_status(security):
    """Get anti-analysis detection status"""
    anti_analysis = security.get('anti_analysis', {})
    obfuscation = security.get('obfuscation_detected', {})

    if anti_analysis.get('detected') or obfuscation.get('packer_detected'):
        return 'Detected'
    return 'Not Detected'
