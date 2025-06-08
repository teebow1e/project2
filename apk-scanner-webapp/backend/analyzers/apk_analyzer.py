import zipfile
import os
import logging
from datetime import datetime

from .manifest_analyzer import ManifestAnalyzer
from .permission_analyzer import PermissionAnalyzer
from .security_analyzer import SecurityAnalyzer
from .malware_detector import MalwareDetector
from .ai_analyzer import AIAnalyzer
from utils.hash_calculator import HashCalculator

logger = logging.getLogger(__name__)

class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.analysis_results = {}

        # Initialize component analyzers
        self.manifest_analyzer = ManifestAnalyzer()
        self.permission_analyzer = PermissionAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.malware_detector = MalwareDetector()
        self.ai_analyzer = AIAnalyzer()
        self.hash_calculator = HashCalculator()

    def analyze(self):
        """Main analysis orchestrator"""
        # try:
        logger.info(f"Starting analysis of {self.apk_path}")

        with zipfile.ZipFile(self.apk_path, 'r') as apk:
            # Basic file information
            self.extract_basic_info(apk)

            # Core analysis components
            self.analysis_results['manifest'] = self.manifest_analyzer.analyze(apk)
            self.analysis_results['permissions'] = self.permission_analyzer.analyze(apk)
            self.analysis_results['security'] = self.security_analyzer.analyze(apk)
            self.analysis_results['malware'] = self.malware_detector.analyze(apk)

            # File structure and hashes
            self.analyze_file_structure(apk)
            self.analysis_results['hashes'] = self.hash_calculator.calculate_hashes(self.apk_path)

            # AI-powered analysis (uses results from other analyzers)
            self.analysis_results['ai_analysis'] = self.ai_analyzer.analyze(self.apk_path)

        logger.info("Analysis completed successfully")
        return self.analysis_results

        # except Exception as e:
        #     logger.error(f"Analysis failed: {str(e)}")
        #     raise

    def extract_basic_info(self, apk):
        """Extract basic APK file information"""
        try:
            info_list = apk.infolist()

            # Calculate compression statistics
            total_compressed = sum(info.compress_size for info in info_list)
            total_uncompressed = sum(info.file_size for info in info_list)

            self.analysis_results['basic_info'] = {
                'file_size': os.path.getsize(self.apk_path),
                'total_files': len(info_list),
                'compressed_size': total_compressed,
                'uncompressed_size': total_uncompressed,
                'compression_ratio': round(
                    (1 - total_compressed / total_uncompressed) * 100, 2
                ) if total_uncompressed > 0 else 0,
                'creation_time': datetime.fromtimestamp(os.path.getctime(self.apk_path)).isoformat(),
                'modification_time': datetime.fromtimestamp(os.path.getmtime(self.apk_path)).isoformat()
            }

        except Exception as e:
            logger.warning(f"Basic info extraction failed: {str(e)}")
            self.analysis_results['basic_info'] = {'error': str(e)}

    def analyze_file_structure(self, apk):
        """Analyze APK file structure"""
        try:
            file_analysis = {
                'native_libraries': [],
                'assets': [],
                'resources': [],
                'dex_files': [],
                'suspicious_files': [],
                'certificates': [],
                'total_entries': 0
            }

            suspicious_patterns = [
                'payload', 'exploit', 'shell', 'root', 'su', 'busybox',
                'dropper', 'loader', 'backdoor', 'keylog'
            ]

            for file_info in apk.infolist():
                filename = file_info.filename
                file_analysis['total_entries'] += 1

                # Categorize files
                if filename.startswith('lib/'):
                    file_analysis['native_libraries'].append({
                        'name': filename,
                        'size': file_info.file_size,
                        'compressed_size': file_info.compress_size
                    })
                elif filename.startswith('assets/'):
                    file_analysis['assets'].append(filename)
                elif filename.startswith('res/'):
                    file_analysis['resources'].append(filename)
                elif filename.endswith('.dex'):
                    file_analysis['dex_files'].append({
                        'name': filename,
                        'size': file_info.file_size
                    })
                elif filename.startswith('META-INF/') and filename.endswith(('.RSA', '.DSA', '.EC')):
                    file_analysis['certificates'].append(filename)

                # Check for suspicious files
                if any(pattern in filename.lower() for pattern in suspicious_patterns):
                    file_analysis['suspicious_files'].append({
                        'name': filename,
                        'reason': 'Contains suspicious pattern',
                        'size': file_info.file_size
                    })

            # Add summary statistics
            file_analysis['summary'] = {
                'native_lib_count': len(file_analysis['native_libraries']),
                'asset_count': len(file_analysis['assets']),
                'resource_count': len(file_analysis['resources']),
                'dex_count': len(file_analysis['dex_files']),
                'suspicious_count': len(file_analysis['suspicious_files']),
                'certificate_count': len(file_analysis['certificates'])
            }

            self.analysis_results['file_structure'] = file_analysis

        except Exception as e:
            logger.warning(f"File structure analysis failed: {str(e)}")
            self.analysis_results['file_structure'] = {'error': str(e)}
