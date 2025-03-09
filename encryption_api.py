#!/usr/bin/env python
"""
API Interface for Advanced Encryption Tool

This script provides a RESTful API interface for the Advanced Encryption Tool,
allowing users to encrypt and decrypt files via HTTP requests.
"""

import os
import json
import base64
import tempfile
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from advanced_encryption_tool import AdvancedEncryptionTool

# Initialize Flask app
app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit file size to 16MB

# Initialize the encryption tool
encryption_tool = AdvancedEncryptionTool()

# Helper function to validate file
def allowed_file(filename):
    """Check if the file is allowed to be uploaded."""
    # Allow all file types
    return True

@app.route('/', methods=['GET'])
def index():
    """Home page with API documentation."""
    api_docs = {
        "name": "Advanced Encryption Tool API",
        "description": "RESTful API for encrypting and decrypting files",
        "endpoints": {
            "/": "API documentation (GET)",
            "/algorithms": "List available encryption algorithms (GET)",
            "/encrypt": "Encrypt a file (POST)",
            "/decrypt": "Decrypt a file (POST)"
        },
        "version": "1.0.0"
    }
    return jsonify(api_docs)

@app.route('/algorithms', methods=['GET'])
def get_algorithms():
    """Get a list of available encryption algorithms."""
    algorithms = {}
    for algo, details in encryption_tool.supported_algorithms.items():
        algorithms[algo] = {
            "name": details["name"],
            "block_size": details["block_size"],
            "key_sizes": details["key_sizes"],
            "default_key_size": details["default_key_size"]
        }
    return jsonify(algorithms)

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    """
    Encrypt a file.
    
    Request parameters:
    - file: The file to encrypt
    - algorithm: The encryption algorithm to use (default: AES)
    - key_option: 'default' or 'custom' (default: default)
    - key_index: The index of the default key (0-4, default: 0)
    - passphrase: The passphrase for custom key derivation (required if key_option is 'custom')
    
    Returns:
    - JSON response with status and download URL
    - Or, the encrypted file directly if download_url is not specified
    """
    # Check if file is included in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    # Check if file is selected
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file and allowed_file(file.filename):
        # Get encryption parameters
        algorithm = request.form.get('algorithm', 'AES')
        key_option = request.form.get('key_option', 'default')
        key_index = int(request.form.get('key_index', 0))
        passphrase = request.form.get('passphrase', None)
        
        # Validate key_option and passphrase
        if key_option == 'custom' and not passphrase:
            return jsonify({"error": "Passphrase is required for custom key"}), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Encrypt the file
            output_file, metadata = encryption_tool.encrypt_file(
                filepath, 
                algorithm=algorithm, 
                key_option=key_option, 
                key_index=key_index, 
                passphrase=passphrase
            )
            
            if output_file:
                # Check if client wants direct download or URL
                if request.form.get('download_url', 'false').lower() == 'true':
                    # Return URL for downloading the file
                    download_url = f"/download/{os.path.basename(output_file)}"
                    return jsonify({
                        "status": "success",
                        "message": "File encrypted successfully",
                        "download_url": download_url,
                        "metadata": metadata
                    })
                else:
                    # Return the encrypted file directly
                    return send_file(output_file, as_attachment=True)
            else:
                return jsonify({"error": "Encryption failed"}), 500
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            # Clean up temporary file
            if os.path.exists(filepath):
                os.remove(filepath)
    
    return jsonify({"error": "Invalid file"}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """
    Decrypt a file.
    
    Request parameters:
    - file: The encrypted file to decrypt
    - metadata_file: The metadata file (optional, if not provided, assumes it's in the same directory as encrypted file)
    
    Returns:
    - JSON response with status and download URL
    - Or, the decrypted file directly if download_url is not specified
    """
    # Check if file is included in the request
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    
    # Check if file is selected
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Check if metadata file is included
    metadata_file = None
    if 'metadata_file' in request.files:
        metadata_file = request.files['metadata_file']
        if metadata_file.filename == '':
            metadata_file = None
    
    if file and allowed_file(file.filename):
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Save metadata file if provided
        metadata_filepath = None
        if metadata_file:
            metadata_filename = secure_filename(metadata_file.filename)
            metadata_filepath = os.path.join(app.config['UPLOAD_FOLDER'], metadata_filename)
            metadata_file.save(metadata_filepath)
        else:
            # Assume metadata file is in the same directory
            metadata_filepath = f"{filepath}.txt"
            if not os.path.exists(metadata_filepath):
                return jsonify({"error": "Metadata file not found"}), 400
        
        try:
            # Decrypt the file
            output_file = encryption_tool.decrypt_file(filepath)
            
            if output_file:
                # Check if client wants direct download or URL
                if request.form.get('download_url', 'false').lower() == 'true':
                    # Return URL for downloading the file
                    download_url = f"/download/{os.path.basename(output_file)}"
                    return jsonify({
                        "status": "success",
                        "message": "File decrypted successfully",
                        "download_url": download_url
                    })
                else:
                    # Return the decrypted file directly
                    return send_file(output_file, as_attachment=True)
            else:
                return jsonify({"error": "Decryption failed"}), 500
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            # Clean up temporary files
            if os.path.exists(filepath):
                os.remove(filepath)
            if metadata_filepath and os.path.exists(metadata_filepath):
                os.remove(metadata_filepath)
    
    return jsonify({"error": "Invalid file"}), 400

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download a file."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)

