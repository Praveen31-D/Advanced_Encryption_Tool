# Advanced Encryption Tool

A comprehensive encryption tool that provides secure text and file encryption using multiple industry-standard algorithms. This project includes a desktop GUI application, a RESTful API, and a client library for easy integration.

## Features

- **Multiple Encryption Algorithms**: Support for AES, DES, 3DES, Blowfish, Twofish, RC4, and RC6
- **Text Encryption**: Encrypt and decrypt text messages
- **File Encryption**: Encrypt and decrypt files with password protection
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **User-Friendly GUI**: Easy-to-use desktop interface
- **API Access**: RESTful API for integration with other applications
- **Security Options**: Customizable encryption parameters

## Components

### Desktop Application

The desktop application provides a graphical user interface for:
- Text encryption/decryption
- File encryption/decryption
- Algorithm selection
- Key/password management

### API Server

The RESTful API provides encryption and decryption services that can be integrated with other applications or accessed remotely.

### API Client

A Python client library for easy interaction with the encryption API.

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages:
- cryptography
- pycryptodome
- tkinter
- flask
- requests

### Setup

1. Clone or download this repository
2. Install the required packages:
```
pip install cryptography pycryptodome flask requests
```
3. Run the application:
```
python run_app.py
```

## Usage

### Desktop Application

1. Run `run_app.py` to start the GUI application
2. Select the encryption algorithm from the dropdown menu
3. Choose between text or file encryption
4. Enter your encryption key or password
5. For text encryption: enter the text and click "Encrypt" or "Decrypt"
6. For file encryption: select the file and click "Encrypt File" or "Decrypt File"

### API Server

Start the API server:
```
python encryption_api.py
```

The API server will start on http://localhost:5000 by default.

### API Client Usage

```python
from encryption_api_client import EncryptionApiClient

# Create a client instance
client = EncryptionApiClient('http://localhost:5000')

# Encrypt text
encrypted_text = client.encrypt_text('Hello World', 'my_secret_key', 'AES')
print(f'Encrypted: {encrypted_text}')

# Decrypt text
decrypted_text = client.decrypt_text(encrypted_text, 'my_secret_key', 'AES')
print(f'Decrypted: {decrypted_text}')
```

## File Descriptions

- **advanced_encryption_tool.py**: Core encryption/decryption functionality
- **encryption_desktop_app.py**: Tkinter-based GUI application
- **encryption_api.py**: Flask-based RESTful API for encryption services
- **encryption_api_client.py**: Python client for the encryption API
- **run_app.py**: Script to launch the desktop application

## Security Notes

- Always use strong, unique passwords for encryption
- The security of your encrypted data depends on keeping your keys/passwords secure
- This tool is for educational and personal use - evaluate security requirements for sensitive data

## License

This project is licensed under the MIT License - see the LICENSE file for details.

