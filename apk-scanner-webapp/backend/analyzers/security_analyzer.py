import logging
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self):
        self.anti_debug_strings = [
            b'android_server_close',
            b'TracerPid',
            b'debugger',
            b'JDWP',
            b'frida',
            b'xposed',
            b'substrate'
        ]

        self.root_detection_strings = [
            b'su',
            b'/system/xbin/su',
            b'/system/bin/su',
            b'busybox',
            b'Superuser.apk',
            b'SuperSU',
            b'RootCloak'
        ]

    def analyze(self, apk):
        """Main security analysis"""
        try:
            security_results = {
                'is_signed': self._check_signature(apk),
                'signature_details': self._get_signature_details(apk),
                'is_debuggable': self._check_debuggable(apk),
                'allows_backup': self._check_backup_allowed(apk),
                'network_security_config': self._check_network_security_config(apk),
                'obfuscation_detected': self._detect_obfuscation(apk),
                'anti_debugging': self._detect_anti_debugging(apk),
                'root_detection': self._detect_root_detection(apk),
                'ssl_pinning': self._detect_ssl_pinning(apk),
                'code_protection': self._analyze_code_protection(apk),
                'anti_analysis': self._detect_anti_analysis_techniques(apk)
            }

            return security_results

        except Exception as e:
            logger.error(f"Security analysis failed: {str(e)}")
            return {'error': str(e)}

    def _check_signature(self, apk):
        """Check if APK is properly signed"""
        try:
            meta_inf_files = [f for f in apk.namelist() if f.startswith('META-INF/')]
            signature_files = [f for f in meta_inf_files if f.endswith(('.RSA', '.DSA', '.EC'))]
            cert_files = [f for f in meta_inf_files if f.endswith('.SF')]

            return {
                'signed': len(signature_files) > 0,
                'signature_files': signature_files,
                'certificate_files': cert_files,
                'manifest_mf_present': 'META-INF/MANIFEST.MF' in meta_inf_files
            }
        except Exception as e:
            logger.warning(f"Signature check failed: {str(e)}")
            return {'signed': False, 'error': str(e)}

    def _get_signature_details(self, apk):
        """Get detailed signature information"""
        try:
            meta_inf_files = [f for f in apk.namelist() if f.startswith('META-INF/')]
            signature_files = [f for f in meta_inf_files if f.endswith(('.RSA', '.DSA', '.EC'))]

            if signature_files:
                cert_file = signature_files[0]
                cert_data = apk.read(cert_file)

                return {
                    'algorithm': cert_file.split('.')[-1],
                    'file_name': cert_file,
                    'size': len(cert_data),
                    'valid': True
                }
        except Exception as e:
            logger.warning(f"Signature details extraction failed: {str(e)}")

        return {'valid': False, 'error': 'No signature details available'}

    def _check_debuggable(self, apk):
        """Check if app is debuggable"""
        try:
            # Try to read manifest for debuggable flag
            manifest_data = apk.read('AndroidManifest.xml')
            # Look for debuggable=true in binary manifest
            return b'debuggable' in manifest_data and b'true' in manifest_data
        except:
            return False

    def _check_backup_allowed(self, apk):
        """Check if backup is allowed"""
        try:
            manifest_data = apk.read('AndroidManifest.xml')
            # Look for allowBackup flag
            return not (b'allowBackup' in manifest_data and b'false' in manifest_data)
        except:
            return True  # Default assumption

    def _check_network_security_config(self, apk):
        """Check for network security configuration"""
        try:
            xml_files = [f for f in apk.namelist() if f.endswith('.xml')]
            network_config_files = [f for f in xml_files if 'network_security_config' in f.lower()]

            if network_config_files:
                return {
                    'present': True,
                    'files': network_config_files,
                    'cleartext_permitted': False
                }

            # Check for security-related XML files
            res_files = [f for f in xml_files if f.startswith('res/')]
            security_related = [f for f in res_files if any(keyword in f.lower()
                               for keyword in ['security', 'network', 'cert', 'ssl'])]

            return {
                'present': len(security_related) > 0,
                'security_files': security_related,
                'cleartext_permitted': True
            }

        except Exception as e:
            logger.warning(f"Network config analysis failed: {str(e)}")
            return {'present': False, 'error': str(e)}

    def _detect_obfuscation(self, apk):
        """Detect code obfuscation techniques"""
        obfuscation_indicators = {
            'string_obfuscation': False,
            'class_name_obfuscation': False,
            'control_flow_obfuscation': False,
            'packer_detected': False,
            'encryption_detected': False,
            'multiple_dex': False
        }

        try:
            file_list = apk.namelist()

            # Check for multiple DEX files
            dex_files = [f for f in file_list if f.endswith('.dex')]
            if len(dex_files) > 1:
                obfuscation_indicators['multiple_dex'] = True
                obfuscation_indicators['packer_detected'] = True

            # Check for suspicious file patterns
            suspicious_patterns = [
                'assets/com.', 'assets/org.', 'assets/bin/',
                'assets/classes.dex', 'assets/payload'
            ]

            for pattern in suspicious_patterns:
                if any(pattern in f for f in file_list):
                    obfuscation_indicators['packer_detected'] = True
                    break

            # Check for obfuscated class names
            java_files = [f for f in file_list if '.class' in f or 'smali' in f]
            if java_files:
                short_names = [f for f in java_files if len(os.path.basename(f).split('.')[0]) <= 2]
                if len(short_names) > len(java_files) * 0.3:
                    obfuscation_indicators['class_name_obfuscation'] = True

            # Check for encrypted files
            encrypted_extensions = ['.enc', '.encrypted', '.bin', '.dat']
            encrypted_files = [f for f in file_list if any(f.endswith(ext) for ext in encrypted_extensions)]
            if encrypted_files:
                obfuscation_indicators['encryption_detected'] = True

        except Exception as e:
            logger.warning(f"Obfuscation detection failed: {str(e)}")

        return obfuscation_indicators

    def _detect_anti_debugging(self, apk):
        """Detect anti-debugging techniques"""
        anti_debug_indicators = []

        try:
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

            for dex_file in dex_files[:2]:
                try:
                    dex_data = apk.read(dex_file)
                    for debug_string in self.anti_debug_strings:
                        if debug_string in dex_data:
                            anti_debug_indicators.append(
                                f"Anti-debug string found: {debug_string.decode('utf-8', errors='ignore')}"
                            )
                except:
                    continue

            # Check native libraries
            native_libs = [f for f in apk.namelist() if f.startswith('lib/') and f.endswith('.so')]
            if native_libs:
                anti_debug_indicators.append("Native libraries present (potential anti-debug)")

        except Exception as e:
            logger.warning(f"Anti-debugging detection failed: {str(e)}")

        return {
            'detected': len(anti_debug_indicators) > 0,
            'indicators': anti_debug_indicators,
            'risk_level': 'high' if len(anti_debug_indicators) > 2 else 'medium' if anti_debug_indicators else 'low'
        }

    def _detect_root_detection(self, apk):
        """Detect root detection mechanisms"""
        root_detection_indicators = []

        try:
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

            for dex_file in dex_files[:2]:
                try:
                    dex_data = apk.read(dex_file)
                    for root_string in self.root_detection_strings:
                        if root_string in dex_data:
                            root_detection_indicators.append(
                                f"Root detection string: {root_string.decode('utf-8', errors='ignore')}"
                            )
                except:
                    continue

        except Exception as e:
            logger.warning(f"Root detection analysis failed: {str(e)}")

        return {
            'detected': len(root_detection_indicators) > 0,
            'indicators': root_detection_indicators
        }

    def _detect_ssl_pinning(self, apk):
        """Detect SSL certificate pinning"""
        ssl_indicators = []

        try:
            # Look for certificate files
            cert_files = [f for f in apk.namelist() if f.endswith(('.crt', '.pem', '.cer'))]
            if cert_files:
                ssl_indicators.append("Certificate files found")

            # Check for SSL pinning libraries/code
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
            ssl_patterns = [
                b'CertificatePinner',
                b'TrustManager',
                b'X509Certificate',
                b'SSLContext'
            ]

            for dex_file in dex_files[:2]:
                try:
                    dex_data = apk.read(dex_file)
                    for pattern in ssl_patterns:
                        if pattern in dex_data:
                            ssl_indicators.append(f"SSL pattern found: {pattern.decode('utf-8', errors='ignore')}")
                            break
                except:
                    continue

        except Exception as e:
            logger.warning(f"SSL pinning detection failed: {str(e)}")

        return {
            'detected': len(ssl_indicators) > 0,
            'indicators': ssl_indicators
        }

    def _analyze_code_protection(self, apk):
        """Analyze code protection mechanisms"""
        protection_features = {
            'string_encryption': False,
            'resource_encryption': False,
            'anti_tampering': False,
            'integrity_checks': False
        }

        try:
            # Check for encrypted strings/resources
            file_list = apk.namelist()
            encrypted_files = [f for f in file_list if '.enc' in f or '.dat' in f]

            if encrypted_files:
                protection_features['resource_encryption'] = True

            # Check for integrity check mechanisms
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
            integrity_patterns = [b'checksum', b'hash', b'integrity', b'tamper']

            for dex_file in dex_files[:1]:
                try:
                    dex_data = apk.read(dex_file)
                    for pattern in integrity_patterns:
                        if pattern in dex_data:
                            protection_features['integrity_checks'] = True
                            break
                except:
                    continue

        except Exception as e:
            logger.warning(f"Code protection analysis failed: {str(e)}")

        return protection_features

    def _detect_anti_analysis_techniques(self, apk):
        """Comprehensive anti-analysis technique detection"""
        techniques = {
            'vm_detection': False,
            'emulator_detection': False,
            'sandbox_detection': False,
            'analysis_tools_detection': False,
            'time_based_evasion': False
        }

        try:
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

            # Patterns for different evasion techniques
            evasion_patterns = {
                'vm_detection': [b'VirtualBox', b'VMware', b'QEMU', b'Xen'],
                'emulator_detection': [b'goldfish', b'emulator', b'android_x86'],
                'sandbox_detection': [b'sandbox', b'anubis', b'cuckoo', b'joesandbox'],
                'analysis_tools': [b'IDA', b'Ghidra', b'radare', b'ollydbg'],
                'time_evasion': [b'sleep', b'delay', b'SystemClock']
            }

            for dex_file in dex_files[:2]:
                try:
                    dex_data = apk.read(dex_file)

                    for technique, patterns in evasion_patterns.items():
                        for pattern in patterns:
                            if pattern in dex_data:
                                if technique == 'analysis_tools':
                                    techniques['analysis_tools_detection'] = True
                                elif technique == 'time_evasion':
                                    techniques['time_based_evasion'] = True
                                else:
                                    techniques[technique] = True
                                break
                except:
                    continue

        except Exception as e:
            logger.warning(f"Anti-analysis detection failed: {str(e)}")

        return techniques
