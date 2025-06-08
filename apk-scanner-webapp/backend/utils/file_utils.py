# utils/file_utils.py
import os
from datetime import datetime

ALLOWED_EXTENSIONS = {'apk'}

def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_bytes(bytes_count):
    """Format bytes to human readable format"""
    if bytes_count == 0:
        return "0 Bytes"

    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB"]
    i = 0
    while bytes_count >= k and i < len(sizes) - 1:
        bytes_count /= k
        i += 1

    return f"{bytes_count:.2f} {sizes[i]}"

def get_file_info(filepath):
    """Get comprehensive file information"""
    stat = os.stat(filepath)
    return {
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
    }
