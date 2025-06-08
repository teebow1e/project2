# utils/hash_calculator.py
import hashlib
import logging

logger = logging.getLogger(__name__)

class HashCalculator:
    def calculate_hashes(self, file_path):
        """Calculate multiple hash types for the file"""
        hashes = {}

        try:
            # Calculate MD5
            with open(file_path, 'rb') as f:
                hashes['md5'] = hashlib.md5(f.read()).hexdigest()

            # Calculate SHA1
            with open(file_path, 'rb') as f:
                hashes['sha1'] = hashlib.sha1(f.read()).hexdigest()

            # Calculate SHA256
            with open(file_path, 'rb') as f:
                hashes['sha256'] = hashlib.sha256(f.read()).hexdigest()

        except Exception as e:
            logger.warning(f"Hash calculation failed: {str(e)}")
            hashes['error'] = str(e)

        return hashes
