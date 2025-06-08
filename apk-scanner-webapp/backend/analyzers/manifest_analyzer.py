# analyzers/manifest_analyzer.py
import logging
import re
import os

logger = logging.getLogger(__name__)

class ManifestAnalyzer:
    def analyze(self, apk):
        """Analyze AndroidManifest.xml"""
        try:
            # Try multiple methods to extract manifest information
            manifest_info = self._parse_binary_manifest(apk)

            # Enhance with file-based analysis
            file_based_info = self._analyze_from_file_structure(apk)
            manifest_info.update(file_based_info)

            return manifest_info

        except Exception as e:
            logger.warning(f"Manifest analysis failed: {str(e)}")
            return self._get_fallback_manifest()

    def _parse_binary_manifest(self, apk):
        """Parse binary AndroidManifest.xml"""
        manifest_info = {
            'package_name': 'com.unknown.app',
            'version_name': '1.0',
            'version_code': '1',
            'min_sdk': '21',
            'target_sdk': '30',
            'activities': [],
            'services': [],
            'receivers': [],
            'permissions': [],
            'uses_features': [],
            'intent_filters': []
        }

        try:
            manifest_data = apk.read('AndroidManifest.xml')

            # Extract strings from binary manifest
            strings = self._extract_strings_from_binary(manifest_data)

            # Find package name
            for string in strings:
                if self._is_valid_package_name(string):
                    manifest_info['package_name'] = string
                    break

            # Find version information
            version_strings = [s for s in strings if re.match(r'^\d+\.\d+', s)]
            if version_strings:
                manifest_info['version_name'] = version_strings[0]

            # Find SDK versions
            sdk_versions = [s for s in strings if s.isdigit() and 14 <= int(s) <= 34]
            if sdk_versions:
                manifest_info['min_sdk'] = min(sdk_versions)
                manifest_info['target_sdk'] = max(sdk_versions)

            # Extract component names
            activity_strings = [s for s in strings if 'Activity' in s and '.' in s]
            service_strings = [s for s in strings if 'Service' in s and '.' in s]
            receiver_strings = [s for s in strings if 'Receiver' in s and '.' in s]

            manifest_info['activities'] = activity_strings[:20]
            manifest_info['services'] = service_strings[:10]
            manifest_info['receivers'] = receiver_strings[:10]

        except Exception as e:
            logger.warning(f"Binary manifest parsing failed: {str(e)}")

        return manifest_info

    def _extract_strings_from_binary(self, manifest_data):
        """Extract readable strings from binary manifest"""
        strings = []
        try:
            # Extract UTF-8 strings
            utf8_strings = re.findall(rb'[\x20-\x7E]{4,}', manifest_data)
            strings.extend([s.decode('utf-8', errors='ignore') for s in utf8_strings])

            # Extract UTF-16 strings (common in Android manifests)
            utf16_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', manifest_data)
            for s in utf16_strings:
                try:
                    decoded = s.decode('utf-16le', errors='ignore').rstrip('\x00')
                    if len(decoded) >= 4:
                        strings.append(decoded)
                except:
                    continue

        except Exception as e:
            logger.warning(f"String extraction failed: {str(e)}")

        return list(set(strings))  # Remove duplicates

    def _is_valid_package_name(self, package_name):
        """Check if string is a valid Android package name"""
        if not package_name or len(package_name) < 5:
            return False

        # Must contain at least one dot
        if '.' not in package_name:
            return False

        # Should start with common prefixes
        valid_prefixes = ['com.', 'org.', 'net.', 'io.', 'app.']
        if not any(package_name.startswith(prefix) for prefix in valid_prefixes):
            return False

        # Check for valid characters (letters, numbers, dots, underscores)
        if not re.match(r'^[a-zA-Z0-9._]+', package_name):
            return False

        # Should have at least 2 parts
        parts = package_name.split('.')
        if len(parts) < 2:
            return False

        return True

    def _analyze_from_file_structure(self, apk):
        """Extract manifest info from APK file structure"""
        file_info = {
            'estimated_components': {},
            'file_structure_analysis': True
        }

        try:
            file_list = apk.namelist()

            # Analyze DEX files for components
            dex_files = [f for f in file_list if f.endswith('.dex')]

            # Count different types of components based on file patterns
            activity_patterns = ['Activity', 'activity']
            service_patterns = ['Service', 'service']
            receiver_patterns = ['Receiver', 'receiver', 'BroadcastReceiver']

            activities = []
            services = []
            receivers = []

            for file_path in file_list:
                filename = os.path.basename(file_path)

                if any(pattern in filename for pattern in activity_patterns):
                    activities.append(file_path)
                elif any(pattern in filename for pattern in service_patterns):
                    services.append(file_path)
                elif any(pattern in filename for pattern in receiver_patterns):
                    receivers.append(file_path)

            file_info['estimated_components'] = {
                'activities': len(activities),
                'services': len(services),
                'receivers': len(receivers),
                'total_dex_files': len(dex_files)
            }

            # Try to infer package name from file structure
            java_files = [f for f in file_list if f.startswith('classes') or f.startswith('smali')]
            if java_files:
                # Extract potential package paths
                for java_file in java_files[:10]:
                    parts = java_file.split('/')
                    if len(parts) >= 4:
                        potential_package = '.'.join(parts[1:4])
                        if self._is_valid_package_name(potential_package):
                            file_info['inferred_package'] = potential_package
                            break

        except Exception as e:
            logger.warning(f"File structure analysis failed: {str(e)}")

        return file_info

    def _get_fallback_manifest(self):
        """Provide fallback manifest info when parsing fails"""
        return {
            'package_name': 'com.unknown.app',
            'app_name': 'Unknown Application',
            'version_name': '1.0',
            'version_code': '1',
            'min_sdk': '21',
            'target_sdk': '30',
            'activities': [],
            'services': [],
            'receivers': [],
            'permissions': [],
            'estimated_components': {
                'activities': 0,
                'services': 0,
                'receivers': 0
            },
            'error': 'Manifest parsing failed'
        }
