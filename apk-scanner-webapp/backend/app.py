from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from datetime import datetime
from werkzeug.utils import secure_filename

from analyzers.apk_analyzer import APKAnalyzer
from utils.file_utils import allowed_file
from utils.response_formatter import format_results_for_frontend

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'apk'}
MAX_CONTENT_LENGTH = 100 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return jsonify({
        "title": "APK Scanner Backend",
        "description": "API Endpoints",
        "endpoints": [
            {"method": "POST", "path": "/analyze", "description": "Upload and analyze APK file"},
            {"method": "GET", "path": "/health", "description": "Health check"},
            {"method": "GET", "path": "/api/info", "description": "API information"}
        ]
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/api/info')
def api_info():
    return jsonify({
        'name': 'APK Security Scanner API',
        'version': '1.0.0',
        'description': 'AI-powered Android APK security analysis',
        'supported_formats': ['APK'],
        'max_file_size': '100MB',
        'features': [
            'Static Analysis',
            'Permission Analysis',
            'Security Assessment',
            'Malware Detection',
            'AI Risk Scoring'
        ]
    })

@app.route('/analyze', methods=['POST'])
def analyze_apk():
    try:
        # Validate request
        if 'apk' not in request.files:
            return jsonify({'error': 'No APK file provided'}), 400

        file = request.files['apk']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only APK files are allowed'}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(filepath)

        try:
            # Initialize analyzer and perform analysis
            analyzer = APKAnalyzer(filepath)
            results = analyzer.analyze()

            # Add metadata
            results['metadata'] = {
                'filename': file.filename,
                'analysis_timestamp': datetime.now().isoformat(),
                'file_size': os.path.getsize(filepath),
                'analyzer_version': '1.0.0'
            }

            # Format results for frontend
            formatted_results = format_results_for_frontend(results)

            # Clean up uploaded file
            os.remove(filepath)

            return jsonify(formatted_results)

        except Exception as e:
            # Clean up on error
            if os.path.exists(filepath):
                os.remove(filepath)
            raise e

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 100MB'}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
