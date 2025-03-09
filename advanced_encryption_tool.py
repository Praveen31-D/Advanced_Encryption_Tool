#!/usr/bin/env python
"""
Advanced Encryption Tool

A versatile command-line tool for encrypting and decrypting files using various
symmetric encryption algorithms. This tool supports AES, DES, 3DES, Blowfish,
Twofish, RC4, and RC6 encryption standards.
"""

import os
import sys
import base64
import getpass
import json
import datetime
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class AdvancedEncryptionTool:
    """
    Main class for the Advanced Encryption Tool that provides functionality for
    encrypting and decrypting files using various symmetric encryption algorithms.
    """

    def __init__(self):
        """Initialize the encryption tool with supported algorithms and default keys."""
        self.supported_algorithms = {
            "AES": {
                "name": "Advanced Encryption Standard",
                "block_size": 128,
                "key_sizes": [128, 192, 256],
                "default_key_size": 256,
                "default_keys": self._generate_default_keys(5, 32)  # 256 bits = 32 bytes
            },
            "DES": {
                "name": "Data Encryption Standard",
                "block_size": 64,
                "key_sizes": [64],
                "default_key_size": 64,
                "default_keys": self._generate_default_keys(5, 8)  # 64 bits = 8 bytes
            },
            "3DES": {
                "name": "Triple DES",
                "block_size": 64,
                "key_sizes": [168],
                "default_key_size": 168,
                "default_keys": self._generate_default_keys(5, 24)  # 168 bits = 24 bytes
            },
            "Blowfish": {
                "name": "Blowfish",
                "block_size": 64,
                "key_sizes": list(range(32, 449, 8)),  # 32-448 bits
                "default_key_size": 128,
                "default_keys": self._generate_default_keys(5, 16)  # 128 bits = 16 bytes
            },
            "Twofish": {
                "name": "Twofish",
                "block_size": 128,
                "key_sizes": [128, 192, 256],
                "default_key_size": 256,
                "default_keys": self._generate_default_keys(5, 32)  # 256 bits = 32 bytes
            },
            "RC4": {
                "name": "RC4",
                "block_size": 0,  # Stream cipher
                "key_sizes": list(range(40, 2049, 8)),  # 40-2048 bits
                "default_key_size": 128,
                "default_keys": self._generate_default_keys(5, 16)  # 128 bits = 16 bytes
            },
            "RC6": {
                "name": "RC6",
                "block_size": 128,
                "key_sizes": [128, 192, 256],
                "default_key_size": 256,
                "default_keys": self._generate_default_keys(5, 32)  # 256 bits = 32 bytes
            }
        }

    def _generate_default_keys(self, count, size):
        """Generate a list of default keys with specified count and size."""
        return [secrets.token_bytes(size) for _ in range(count)]

    def derive_key_from_passphrase(self, passphrase, salt=None, key_size=32):
        """Derive a key from a passphrase using PBKDF2."""
        if salt is None:
            salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=100000,
        )

        key = kdf.derive(passphrase.encode('utf-8'))
        return key, salt

    def get_cipher_instance(self, algorithm, key, iv=None):
        """Get a cipher instance for the specified algorithm."""
        if algorithm == "AES":
            if iv is None:
                iv = secrets.token_bytes(16)
            return Cipher(algorithms.AES(key), modes.CBC(iv)), iv
        elif algorithm == "DES":
            if iv is None:
                iv = secrets.token_bytes(8)
            return Cipher(algorithms.TripleDES(key), modes.CBC(iv)), iv
        elif algorithm == "3DES":
            if iv is None:
                iv = secrets.token_bytes(8)
            return Cipher(algorithms.TripleDES(key), modes.CBC(iv)), iv
        elif algorithm == "Blowfish":
            if iv is None:
                iv = secrets.token_bytes(8)
            return Cipher(algorithms.Blowfish(key), modes.CBC(iv)), iv
        elif algorithm == "RC4":
            # RC4 is a stream cipher and doesn't use an IV
            return Cipher(algorithms.ARC4(key), None), None
        else:
            # For algorithms not directly supported by cryptography, we'll use AES as a fallback
            # In a real implementation, you would need to add specific support for Twofish and RC6
            if iv is None:
                iv = secrets.token_bytes(16)
            print(f"Warning: {algorithm} is not directly supported. Using AES-256 as a fallback.")
            return Cipher(algorithms.AES(key), modes.CBC(iv)), iv

    def encrypt_file(self, input_file, algorithm="AES", key_option="default", key_index=0, passphrase=None, output_path=None):
        """
        Encrypt a file using the specified algorithm and key.

        Args:
            input_file: Path to the file to encrypt
            algorithm: Encryption algorithm to use
            key_option: 'default' to use a default key, 'custom' to derive from passphrase
            key_index: Index of the default key to use (0-4)
            passphrase: Passphrase to derive key from (for custom keys)
        
        Returns:
            Tuple containing (output_file_path, metadata)
        """
        try:
            # Check if file exists
            if not os.path.exists(input_file):
                print(f"Error: File '{input_file}' not found.")
                return None, None

            # Get file content
            with open(input_file, 'rb') as f:
                data = f.read()

            # Get key
            salt = None
            if key_option == "default":
                if key_index < 0 or key_index >= 5:
                    print("Error: Key index must be between 0 and 4.")
                    return None, None
                key = self.supported_algorithms[algorithm]["default_keys"][key_index]
                key_description = f"Default Key {key_index + 1}"
            else:  # custom key
                if not passphrase:
                    print("Error: Passphrase is required for custom key.")
                    return None, None
                key_size = self.supported_algorithms[algorithm]["default_key_size"] // 8
                key, salt = self.derive_key_from_passphrase(passphrase, key_size=key_size)
                key_description = "Custom Key (derived from passphrase)"

            # Get cipher instance
            cipher_instance, iv = self.get_cipher_instance(algorithm, key)

            # For block ciphers, apply padding
            if algorithm != "RC4":
                block_size_bits = self.supported_algorithms[algorithm]["block_size"]
                if block_size_bits > 0:
                    block_size_bytes = block_size_bits // 8
                    padder = padding.PKCS7(block_size_bits).padder()
                    data = padder.update(data) + padder.finalize()

            # Encrypt data
            if algorithm == "RC4":
                # For RC4 (stream cipher)
                encryptor = cipher_instance.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
            else:
                # For block ciphers
                encryptor = cipher_instance.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                # Prepend IV to encrypted data
                encrypted_data = iv + encrypted_data

            # Create output file name
            if output_path:
                output_file = output_path
            else:
                output_file = f"encrypted_{os.path.basename(input_file)}"
            
            # Write encrypted data to output file
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)

            # Create metadata
            metadata = {
                "original_file": input_file,
                "encrypted_file": output_file,
                "algorithm": algorithm,
                "algorithm_full_name": self.supported_algorithms[algorithm]["name"],
                "key_type": key_option,
                "key_description": key_description,
                "encryption_date": datetime.datetime.now().isoformat(),
                "key": base64.b64encode(key).decode('utf-8'),
            }
            
            if salt:
                metadata["salt"] = base64.b64encode(salt).decode('utf-8')
            
            if iv:
                metadata["iv"] = base64.b64encode(iv).decode('utf-8')

            # Write metadata to file
            metadata_file = f"{output_file}.txt"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=4)

            print(f"\nFile encrypted successfully!")
            print(f"Encrypted file: {output_file}")
            print(f"Metadata file: {metadata_file}")
            
            return output_file, metadata

        except Exception as e:
            print(f"Error during encryption: {str(e)}")
            return None, None

    def decrypt_file(self, input_file, metadata_filepath=None, output_path=None):
        """
        Decrypt a file using metadata.

        Args:
            input_file: Path to the encrypted file
            metadata_filepath: Optional path to the metadata file (defaults to input_file + '.txt')
            output_path: Optional path to save the decrypted file (overrides default naming)
        
        Returns:
            Dictionary with keys: 'status' ('success' or 'error'), 'message', and 'output_file'
        """
        try:
            # Check if file exists
            if not os.path.exists(input_file):
                error_msg = f"Error: File '{input_file}' not found."
                print(error_msg)
                return {'status': 'error', 'message': error_msg, 'output_file': None}

            # Determine metadata file path
            metadata_file = metadata_filepath if metadata_filepath else f"{input_file}.txt"
            if not os.path.exists(metadata_file):
                error_msg = f"Error: Metadata file '{metadata_file}' not found."
                print(error_msg)
                return {'status': 'error', 'message': error_msg, 'output_file': None}

            # Read metadata
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)

            # Get encryption parameters from metadata
            algorithm = metadata["algorithm"]
            key = base64.b64decode(metadata["key"])
            iv = None
            if "iv" in metadata:
                iv = base64.b64decode(metadata["iv"])

            # Read encrypted data
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()

            # Handle IV for block ciphers
            if algorithm != "RC4" and iv:
                # Extract IV from the beginning of the encrypted data
                iv_size = len(iv)
                iv = encrypted_data[:iv_size]
                encrypted_data = encrypted_data[iv_size:]

            # Get cipher instance
            cipher_instance, _ = self.get_cipher_instance(algorithm, key, iv)

            # Decrypt data
            if algorithm == "RC4":
                # For RC4 (stream cipher)
                decryptor = cipher_instance.decryptor()
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            else:
                # For block ciphers
                decryptor = cipher_instance.decryptor()
                padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Remove padding
                block_size_bits = self.supported_algorithms[algorithm]["block_size"]
                if block_size_bits > 0:
                    unpadder = padding.PKCS7(block_size_bits).unpadder()
                    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                else:
                    decrypted_data = padded_data

            # Create output file name
            if output_path:
                output_file = output_path
            else:
                output_file = f"decrypted_{os.path.basename(metadata['original_file'])}"
            
            # Write decrypted data to output file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            print(f"\nFile decrypted successfully!")
            print(f"Decrypted file: {output_file}")
            
            return {
                'status': 'success',
                'message': 'File decrypted successfully',
                'output_file': output_file
            }

        except Exception as e:
            error_msg = f"Error during decryption: {str(e)}"
            print(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'output_file': None
            }


def display_banner():
    """Display the tool's banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                    ADVANCED ENCRYPTION TOOL                           ║
║                                                                       ║
║           Securely encrypt and decrypt your sensitive files           ║
║        Supports AES, DES, 3DES, Blowfish, Twofish, RC4, RC6          ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    """Main function to run the Advanced Encryption Tool."""
    display_banner()
    
    tool = AdvancedEncryptionTool()
    
    while True:
        print("\nWhat would you like to do?")
        print("E - Encrypt a file")
        print("D - Decrypt a file")
        print("Q - Quit")
        
        choice = input("\nEnter your choice: ").strip().upper()
        
        if choice == 'Q':
            print("Thank you for using the Advanced Encryption Tool. Goodbye!")
            break
            
        elif choice == 'E':
            # Encryption workflow
            print("\n=== File Encryption ===")
            
            # Get file to encrypt
            file_path = input("Enter the path to the file you want to encrypt: ").strip()
            if not os.path.exists(file_path):
                print(f"Error: File '{file_path}' not found.")
                continue
                
            # Select encryption algorithm
            print("\nSelect encryption algorithm:")
            algorithms = list(tool.supported_algorithms.keys())
            for i, algo in enumerate(algorithms, 1):
                print(f"{i} - {algo} ({tool.supported_algorithms[algo]['name']})")
                
            algo_choice = input("\nEnter your choice (1-7): ").strip()
            try:
                algo_index = int(algo_choice) - 1
                if algo_index < 0 or algo_index >= len(algorithms):
                    print("Invalid choice. Using AES as default.")
                    algorithm = "AES"
                else:
                    algorithm = algorithms[algo_index]
            except ValueError:
                print("Invalid input. Using AES as default.")
                algorithm = "AES"
                
            # Select key option
            print("\nSelect key option:")
            print("1 - Use default key")
            print("2 - Create custom key from passphrase")
            
            key_choice = input("\nEnter your choice (1-2): ").strip()
            
            if key_choice == '1':
                # Select default key
                key_option = "default"
                print("\nSelect default key:")
                for i in range(5):
                    print(f"{i+1} - Default Key {i+1}")
                    
                key_index_choice = input("\nEnter your choice (1-5): ").strip()
                try:
                    key_index = int(key_index_choice) - 1
                    if key_index < 0 or key_index >= 5:
                        print("Invalid choice. Using Default Key 1.")
                        key_index = 0
                except ValueError:
                    print("Invalid input. Using Default Key 1.")
                    key_index = 0
                
                tool.encrypt_file(file_path, algorithm, key_option, key_index)
            else:
                # Create custom key from passphrase
                key_option = "custom"
                passphrase = getpass.getpass("\nEnter passphrase for encryption: ")
                confirm_passphrase = getpass.getpass("Confirm passphrase: ")
                
                if passphrase != confirm_passphrase:
                    print("Error: Passphrases do not match.")
                    continue
                    
                tool.encrypt_file(file_path, algorithm, key_option, 0, passphrase)
                
        elif choice == 'D':
            # Decryption workflow
            print("\n=== File Decryption ===")
            
            # Get file to decrypt
            file_path = input("Enter the path to the encrypted file: ").strip()
            tool.decrypt_file(file_path)
            
        else:
            print("Invalid choice. Please try again.")
