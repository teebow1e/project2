import logging
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

class PermissionAnalyzer:
    def __init__(self):
        self.android_permissions = self._load_permission_database()

    def _load_permission_database(self):
        """Load comprehensive Android permissions database"""
        return {
            # High Risk Permissions - Privacy & Security Critical
            'CAMERA': {'risk': 'high', 'description': 'Access device camera', 'category': 'privacy'},
            'RECORD_AUDIO': {'risk': 'high', 'description': 'Record audio from microphone', 'category': 'privacy'},
            'ACCESS_FINE_LOCATION': {'risk': 'high', 'description': 'Access precise location (GPS)', 'category': 'location'},
            'ACCESS_BACKGROUND_LOCATION': {'risk': 'high', 'description': 'Access location in background', 'category': 'location'},
            'READ_CONTACTS': {'risk': 'high', 'description': 'Read contact information', 'category': 'personal_data'},
            'WRITE_CONTACTS': {'risk': 'high', 'description': 'Modify contact information', 'category': 'personal_data'},
            'READ_SMS': {'risk': 'high', 'description': 'Read SMS messages', 'category': 'messaging'},
            'SEND_SMS': {'risk': 'high', 'description': 'Send SMS messages', 'category': 'messaging'},
            'CALL_PHONE': {'risk': 'high', 'description': 'Make phone calls', 'category': 'phone'},
            'READ_CALL_LOG': {'risk': 'high', 'description': 'Read call history', 'category': 'phone'},
            'WRITE_CALL_LOG': {'risk': 'high', 'description': 'Modify call history', 'category': 'phone'},

            # Administrative Permissions - Very High Risk
            'DEVICE_ADMIN': {'risk': 'high', 'description': 'Device administrator privileges', 'category': 'admin'},
            'BIND_DEVICE_ADMIN': {'risk': 'high', 'description': 'Bind to device admin service', 'category': 'admin'},
            'WRITE_SETTINGS': {'risk': 'high', 'description': 'Modify system settings', 'category': 'system'},
            'WRITE_SECURE_SETTINGS': {'risk': 'high', 'description': 'Modify secure system settings', 'category': 'system'},
            'INSTALL_PACKAGES': {'risk': 'high', 'description': 'Install other applications', 'category': 'system'},
            'DELETE_PACKAGES': {'risk': 'high', 'description': 'Uninstall applications', 'category': 'system'},
            'MANAGE_ACCOUNTS': {'risk': 'high', 'description': 'Manage device accounts', 'category': 'accounts'},

            # Medium Risk Permissions
            'ACCESS_COARSE_LOCATION': {'risk': 'medium', 'description': 'Access approximate location', 'category': 'location'},
            'READ_PHONE_STATE': {'risk': 'medium', 'description': 'Read phone state and identity', 'category': 'device_info'},
            'RECEIVE_SMS': {'risk': 'medium', 'description': 'Receive SMS messages', 'category': 'messaging'},
            'READ_CALENDAR': {'risk': 'medium', 'description': 'Read calendar events', 'category': 'personal_data'},
            'WRITE_CALENDAR': {'risk': 'medium', 'description': 'Add/modify calendar events', 'category': 'personal_data'},
            'WRITE_EXTERNAL_STORAGE': {'risk': 'medium', 'description': 'Write to external storage', 'category': 'storage'},
            'READ_EXTERNAL_STORAGE': {'risk': 'medium', 'description': 'Read from external storage', 'category': 'storage'},
            'BODY_SENSORS': {'risk': 'medium', 'description': 'Access body sensors (heart rate, etc)', 'category': 'sensors'},
            'GET_ACCOUNTS': {'risk': 'medium', 'description': 'Access account list on device', 'category': 'accounts'},
            'USE_FINGERPRINT': {'risk': 'medium', 'description': 'Use fingerprint hardware', 'category': 'biometric'},
            'USE_BIOMETRIC': {'risk': 'medium', 'description': 'Use biometric hardware', 'category': 'biometric'},
            'SYSTEM_ALERT_WINDOW': {'risk': 'medium', 'description': 'Display over other apps', 'category': 'display'},
            'CHANGE_WIFI_STATE': {'risk': 'medium', 'description': 'Change Wi-Fi state', 'category': 'network'},
            'CHANGE_NETWORK_STATE': {'risk': 'medium', 'description': 'Change network state', 'category': 'network'},
            'BLUETOOTH_ADMIN': {'risk': 'medium', 'description': 'Administer Bluetooth settings', 'category': 'hardware'},

            # Low Risk Permissions
            'INTERNET': {'risk': 'low', 'description': 'Access internet connection', 'category': 'network'},
            'ACCESS_NETWORK_STATE': {'risk': 'low', 'description': 'View network state', 'category': 'network'},
            'ACCESS_WIFI_STATE': {'risk': 'low', 'description': 'View Wi-Fi state', 'category': 'network'},
            'VIBRATE': {'risk': 'low', 'description': 'Control device vibration', 'category': 'hardware'},
            'WAKE_LOCK': {'risk': 'low', 'description': 'Prevent device from sleeping', 'category': 'power'},
            'FLASHLIGHT': {'risk': 'low', 'description': 'Control camera flash', 'category': 'hardware'},
            'NFC': {'risk': 'low', 'description': 'Access NFC functionality', 'category': 'hardware'},
            'BLUETOOTH': {'risk': 'low', 'description': 'Access Bluetooth functionality', 'category': 'hardware'},
            'FOREGROUND_SERVICE': {'risk': 'low', 'description': 'Run foreground service', 'category': 'service'},
            'RECEIVE_BOOT_COMPLETED': {'risk': 'low', 'description': 'Start on device boot', 'category': 'system'}
        }

    def analyze(self, apk):
        """Comprehensive permission analysis"""
        try:
            detected_permissions = []

            # Method 1: Try to extract from manifest
            manifest_permissions = self._extract_from_manifest(apk)
            detected_permissions.extend(manifest_permissions)

            # Method 2: Analyze DEX files for permission usage
            dex_permissions = self._analyze_dex_permissions(apk)
            for perm in dex_permissions:
                if not any(p['name'] == perm for p in detected_permissions):
                    detected_permissions.append(self._create_permission_info(perm))

            # Method 3: Infer from file structure if no permissions found
            if not detected_permissions:
                inferred_permissions = self._infer_from_structure(apk)
                detected_permissions.extend(inferred_permissions)

            # Calculate statistics
            return self._calculate_permission_stats(detected_permissions)

        except Exception as e:
            logger.error(f"Permission analysis failed: {str(e)}")
            return self._get_fallback_permissions()

    def _extract_from_manifest(self, apk):
        """Extract permissions from AndroidManifest.xml"""
        permissions = []
        try:
            manifest_data = apk.read('AndroidManifest.xml')
            extracted_perms = self._parse_binary_manifest(manifest_data)

            for perm in extracted_perms:
                perm_info = self._create_permission_info(perm)
                if perm_info:
                    permissions.append(perm_info)

        except Exception as e:
            logger.warning(f"Manifest permission extraction failed: {str(e)}")

        return permissions

    def _parse_binary_manifest(self, manifest_data):
        """Parse binary manifest for permission strings"""
        permissions = set()
        try:
            # Look for permission patterns in binary data
            permission_patterns = [
                rb'android\.permission\.[A-Z_]+',
                rb'com\.android\.permission\.[A-Z_]+'
            ]

            for pattern in permission_patterns:
                matches = re.findall(pattern, manifest_data)
                for match in matches:
                    perm_full = match.decode('utf-8', errors='ignore')
                    perm_name = perm_full.split('.')[-1]
                    if perm_name and perm_name.isupper():
                        permissions.add(perm_name)

        except Exception as e:
            logger.warning(f"Binary manifest parsing failed: {str(e)}")

        return list(permissions)

    def _analyze_dex_permissions(self, apk):
        """Analyze DEX files for permission usage indicators"""
        permissions = set()

        try:
            dex_files = [f for f in apk.namelist() if f.endswith('.dex')]

            # Permission usage patterns in code
            api_permission_map = {
                b'Camera': 'CAMERA',
                b'camera': 'CAMERA',
                b'LocationManager': 'ACCESS_FINE_LOCATION',
                b'GPS': 'ACCESS_FINE_LOCATION',
                b'SmsManager': 'SEND_SMS',
                b'sendTextMessage': 'SEND_SMS',
                b'TelephonyManager': 'READ_PHONE_STATE',
                b'ContactsContract': 'READ_CONTACTS',
                b'AudioRecord': 'RECORD_AUDIO',
                b'MediaRecorder': 'RECORD_AUDIO',
                b'checkSelfPermission': 'RUNTIME_PERMISSIONS',
                b'requestPermissions': 'RUNTIME_PERMISSIONS'
            }

            for dex_file in dex_files[:3]:  # Limit to first 3 DEX files
                try:
                    dex_data = apk.read(dex_file)

                    for api_pattern, permission in api_permission_map.items():
                        if api_pattern in dex_data:
                            permissions.add(permission)

                except Exception as e:
                    logger.warning(f"DEX analysis failed for {dex_file}: {str(e)}")

        except Exception as e:
            logger.warning(f"DEX permission analysis failed: {str(e)}")

        return list(permissions)

    def _infer_from_structure(self, apk):
        """Infer permissions from APK file structure"""
        permissions = []
        file_list = apk.namelist()

        # Inference rules based on file patterns
        inference_rules = {
            'CAMERA': ['camera', 'Camera', 'photo', 'image'],
            'ACCESS_FINE_LOCATION': ['location', 'gps', 'GPS', 'maps'],
            'RECORD_AUDIO': ['audio', 'sound', 'microphone', 'record'],
            'READ_CONTACTS': ['contacts', 'addressbook'],
            'INTERNET': ['http', 'network', 'api', 'www'],
            'VIBRATE': ['vibrat', 'haptic'],
            'WRITE_EXTERNAL_STORAGE': ['storage', 'file', 'sdcard']
        }

        for permission, patterns in inference_rules.items():
            if any(any(pattern in filename for pattern in patterns) for filename in file_list):
                perm_info = self._create_permission_info(permission)
                if perm_info:
                    permissions.append(perm_info)

        # Always assume basic network permissions for modern apps
        basic_permissions = ['INTERNET', 'ACCESS_NETWORK_STATE']
        for perm in basic_permissions:
            if not any(p['name'] == perm for p in permissions):
                perm_info = self._create_permission_info(perm)
                if perm_info:
                    permissions.append(perm_info)

        return permissions

    def _create_permission_info(self, permission_name):
        """Create permission info object"""
        if permission_name in self.android_permissions:
            perm_info = self.android_permissions[permission_name].copy()
            perm_info['name'] = permission_name
            return perm_info
        else:
            # Unknown permission
            return {
                'name': permission_name,
                'risk': 'medium',
                'description': 'Custom or unknown permission',
                'category': 'unknown'
            }

    def _calculate_permission_stats(self, permissions):
        """Calculate permission statistics and risk assessment"""
        risk_summary = {'high': 0, 'medium': 0, 'low': 0}
        category_summary = defaultdict(int)
        dangerous_permissions = []

        for perm in permissions:
            risk_summary[perm['risk']] += 1
            category_summary[perm['category']] += 1

            if perm['risk'] == 'high':
                dangerous_permissions.append(perm)

        return {
            'detected_permissions': permissions,
            'total_permissions': len(permissions),
            'risk_summary': risk_summary,
            'category_summary': dict(category_summary),
            'dangerous_permissions': dangerous_permissions,
            'risk_score': self._calculate_risk_score(risk_summary),
            'privacy_impact': self._assess_privacy_impact(permissions)
        }

    def _calculate_risk_score(self, risk_summary):
        """Calculate numerical risk score based on permissions"""
        score = (risk_summary['high'] * 20 +
                risk_summary['medium'] * 10 +
                risk_summary['low'] * 2)
        return min(score, 100)  # Cap at 100

    def _assess_privacy_impact(self, permissions):
        """Assess privacy impact of requested permissions"""
        privacy_categories = ['privacy', 'personal_data', 'location', 'messaging']
        privacy_perms = [p for p in permissions if p['category'] in privacy_categories]

        if len(privacy_perms) >= 5:
            return 'HIGH'
        elif len(privacy_perms) >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _get_fallback_permissions(self):
        """Provide fallback permission analysis when detection fails"""
        return {
            'detected_permissions': [
                self._create_permission_info('INTERNET'),
                self._create_permission_info('ACCESS_NETWORK_STATE')
            ],
            'total_permissions': 2,
            'risk_summary': {'high': 0, 'medium': 0, 'low': 2},
            'category_summary': {'network': 2},
            'dangerous_permissions': [],
            'risk_score': 4,
            'privacy_impact': 'LOW',
            'error': 'Permission detection failed, showing minimal permissions'
        }
