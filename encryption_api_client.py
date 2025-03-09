#!/usr/bin/env python
"""
Advanced Encryption Tool API Client

This script demonstrates how to use the Advanced Encryption Tool API
to encrypt and decrypt files programmatically.
"""

import os
import sys
import requests
import json

# API endpoint
API_BASE_URL = "http://localhost:5000"

def get_algorithms():
    """Get a list of available encryption algorithms from the API."""
    response = requests.get(f"{API_BASE_URL}/algorithms")
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def encrypt_file(file_path, algorithm="AES", key_option="default", key_index=0, passphrase=None):
    """
    Encrypt a file using the API.
    
    Args:
        file_path: Path to the file to encrypt
        algorithm: Encryption algorithm to use (default: AES)
        key_option: 'default' or 'custom' (default: default)
        key_index: Index of the default key (0-4, default: 0)
        passphrase: Passphrase for custom key derivation (required if key_option is 'custom')
    
    Returns:
        Tuple containing (success, result)
        where result is either an error message or (encrypted_file_path, metadata_file_path)
    """
    # Check if file exists
    if not os.path.exists(file_path):
        return False, f"File '{file_path}' not found."
    
    # Prepare request data
    files = {'file': open(file_path, 'rb')}
    data = {
        'algorithm': algorithm,
        'key_option': key_option,
        'key_index': key_index,
        'download_url': 'true'  # Request a download URL instead of direct download
    }
    
    if key_option == 'custom' and passphrase:
        data['passphrase'] = passphrase
    
    # Send request to API
    try:
        response = requests.post(f"{API_BASE_URL}/encrypt", files=files, data=data)
        files['file'].close()
        
        if response.status_code == 200:
            result = response.json()
            
            # Download the encrypted file
            encrypted_file_name = os.path.basename(result['download_url'])
            encrypted_file_path = os.path.join(os.path.dirname(file_path), encrypted_file_name)
            download_response = requests.get(f"{API_BASE_URL}{result['download_url']}")
            
            if download_response.status_code == 200:
                with open(encrypted_file_path, 'wb') as f:
                    f.write(download_response.content)
                
                # Save metadata to file
                metadata_file_path = f"{encrypted_file_path}.txt"
                with open(metadata_file_path, 'w') as f:
                    json.dump(result['metadata'], f, indent=4)
                
                return True, (encrypted_file_path, metadata_file_path)
            else:
                return False, f"Error downloading encrypted file: {download_response.status_code} - {download_response.text}"
        else:
            return False, f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def decrypt_file(encrypted_file_path, metadata_file_path=None):
    """
    Decrypt a file using the API.
    
    Args:
        encrypted_file_path: Path to the encrypted file
        metadata_file_path: Path to the metadata file (optional)
    
    Returns:
        Tuple containing (success, result)
        where result is either an error message or decrypted file path
    """
    # Check if encrypted file exists
    if not os.path.exists(encrypted_file_path):
        return False, f"File '{encrypted_file_path}' not found."
    
    # Check if metadata file exists (if provided)
    if metadata_file_path and not os.path.exists(metadata_file_path):
        return False, f"Metadata file '{metadata_file_path}' not found."
    
    # Prepare request data
    files = {'file': open(encrypted_file_path, 'rb')}
    if metadata_file_path:
        files['metadata_file'] = open(metadata_file_path, 'rb')
    
    data = {
        'download_url': 'true'  # Request a download URL instead of direct download
    }
    
    # Send request to API
    try:
        response = requests.post(f"{API_BASE_URL}/decrypt", files=files, data=data)
        files['file'].close()
        if metadata_file_path and 'metadata_file' in files:
            files['metadata_file'].close()
        
        if response.status_code == 200:
            result = response.json()
            
            # Download the decrypted file
            decrypted_file_name = os.path.basename(result['download_url'])
            decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), decrypted_file_name)
            download_response = requests.get(f"{API_BASE_URL}{result['download_url']}")
            
            if download_response.status_code == 200:
                with open(decrypted_file_path, 'wb') as f:
                    f.write(download_response.content)
                return True, decrypted_file_path
            else:
                return False, f"Error downloading decrypted file: {download_response.status_code} - {download_response.text}"
        else:
            return False, f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return False, f"Error: {str(e)}"


# Example usage
if __name__ == "__main__":
    print("Advanced Encryption Tool API Client Example")
    print("==========================================")
    
    # Check if the API is running
    try:
        response = requests.get(f"{API_BASE_URL}/")
        if response.status_code != 200:
            print(f"Error: API server not responding correctly. Status code: {response.status_code}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to API server at {API_BASE_URL}")
        print("Make sure the server is running with: python encryption_api.py")
        sys.exit(1)
    
    # Get available algorithms
    print("\n1. Fetching available encryption algorithms...")
    algorithms = get_algorithms()
    if algorithms:
        print("Available algorithms:")
        for algo, details in algorithms.items():
            print(f"  - {algo}: {details['name']} (Key sizes: {details['key_sizes']})")
    
    # Example file to encrypt/decrypt
    example_file = "example.txt"
    
    # Create an example file if it doesn't exist
    if not os.path.exists(example_file):
        print(f"\nCreating example file '{example_file}'...")
        with open(example_file, "w") as f:
            f.write("This is a test file for the Advanced Encryption Tool API.\n")
            f.write("This text will be encrypted and then decrypted using the API.\n")
    
    # Example 1: Encrypt a file with default key
    print("\n2. Example 1: Encrypting a file with default key (AES algorithm)...")
    success, result = encrypt_file(example_file, algorithm="AES", key_option="default", key_index=0)
    
    if success:
        encrypted_file_path, metadata_file_path = result
        print(f"File encrypted successfully!")
        print(f"Encrypted file: {encrypted_file_path}")
        print(f"Metadata file: {metadata_file_path}")
        
        # Example 2: Decrypt the file
        print("\n3. Example 2: Decrypting the encrypted file...")
        success, decrypted_file_path = decrypt_file(encrypted_file_path, metadata_file_path)
        
        if success:
            print(f"File decrypted successfully!")
            print(f"Decrypted file: {decrypted_file_path}")
            
            # Display the contents of the decrypted file
            print("\nContents of the decrypted file:")
            with open(decrypted_file_path, 'r') as f:
                print(f.read())
        else:
            print(f"Decryption failed: {decrypted_file_path}")
    else:
        print(f"Encryption failed: {result}")
    
    # Example 3: Encrypt a file with custom key
    print("\n4. Example 3: Encrypting a file with custom passphrase (Blowfish algorithm)...")
    custom_passphrase = "my_secret_passphrase"
    success, result = encrypt_file(
        example_file, 
        algorithm="Blowfish", 
        key_option="custom", 
        passphrase=custom_passphrase
    )
    
    if success:
        encrypted_file_path, metadata_file_path = result
        print(f"File encrypted successfully with custom passphrase!")
        print(f"Encrypted file: {encrypted_file_path}")
        print(f"Metadata file: {metadata_file_path}")
        
        # Example 4: Decrypt the file encrypted with custom key
        print("\n5. Example 4: Decrypting the file encrypted with custom passphrase...")
        success, decrypted_file_path = decrypt_file(encrypted_file_path, metadata_file_path)
        
        if success:
            print(f"File decrypted successfully!")
            print(f"Decrypted file: {decrypted_file_path}")
        else:
            print(f"Decryption failed: {decrypted_file_path}")
    else:
        print(f"Encryption failed: {result}")
    
    print("\nAdvanced Encryption Tool API Client Example completed.")

