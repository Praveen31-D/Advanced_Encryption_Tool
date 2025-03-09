import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from advanced_encryption_tool import AdvancedEncryptionTool

class AdvancedEncryptionToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Initialize the encryption tool
        self.encryption_tool = AdvancedEncryptionTool()
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.about_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        self.notebook.add(self.about_frame, text="About")
        
        # Create the UI components
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_about_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_encrypt_tab(self):
        """Create the encryption tab with all its components"""
        # Main container
        main_frame = ttk.Frame(self.encrypt_frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File path entry and browse button
        ttk.Label(file_frame, text="File to encrypt:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.encrypt_file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.encrypt_file_path, width=60).grid(column=1, row=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_encrypt_file).grid(column=2, row=0, padx=5, pady=5)
        
        # Algorithm selection frame
        algo_frame = ttk.LabelFrame(main_frame, text="Encryption Algorithm", padding=10)
        algo_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Algorithm dropdown
        ttk.Label(algo_frame, text="Select algorithm:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.algorithm_var = tk.StringVar(value="AES")
        algorithms = list(self.encryption_tool.supported_algorithms.keys())
        ttk.Combobox(algo_frame, textvariable=self.algorithm_var, values=algorithms, state="readonly", width=20).grid(
            column=1, row=0, sticky=tk.W, padx=5, pady=5)
        
        # Key options frame
        key_frame = ttk.LabelFrame(main_frame, text="Key Options", padding=10)
        key_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Radio buttons for key type
        self.key_option = tk.StringVar(value="default")
        ttk.Radiobutton(key_frame, text="Use Default Key", variable=self.key_option, value="default", 
                        command=self.toggle_key_options).grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Radiobutton(key_frame, text="Use Custom Passphrase", variable=self.key_option, value="custom", 
                        command=self.toggle_key_options).grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        
        # Default key selection
        self.default_key_frame = ttk.Frame(key_frame)
        self.default_key_frame.grid(column=0, row=1, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(self.default_key_frame, text="Select default key:").pack(side=tk.LEFT, padx=(0, 5))
        self.key_index_var = tk.IntVar(value=0)
        ttk.Combobox(self.default_key_frame, textvariable=self.key_index_var, values=[1, 2, 3, 4, 5], 
                    width=5, state="readonly").pack(side=tk.LEFT, padx=5)
        
        # Custom passphrase entry
        self.custom_key_frame = ttk.Frame(key_frame)
        self.custom_key_frame.grid(column=0, row=2, columnspan=2, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(self.custom_key_frame, text="Enter passphrase:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.passphrase_var = tk.StringVar()
        ttk.Entry(self.custom_key_frame, textvariable=self.passphrase_var, show="*", width=30).grid(
            column=1, row=0, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.custom_key_frame, text="Confirm passphrase:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        self.confirm_passphrase_var = tk.StringVar()
        ttk.Entry(self.custom_key_frame, textvariable=self.confirm_passphrase_var, show="*", width=30).grid(
            column=1, row=1, sticky=tk.W, padx=5, pady=5)
        
        # Toggle initial state
        self.toggle_key_options()
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Encrypt button
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_file, width=15).pack(side=tk.RIGHT, padx=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status text widget
        self.encrypt_status_text = tk.Text(status_frame, height=10, width=70, wrap="word")
        self.encrypt_status_text.pack(fill=tk.BOTH, expand=True)
        self.encrypt_status_text.config(state="disabled")
    
    def create_decrypt_tab(self):
        """Create the decryption tab with all its components"""
        # Main container
        main_frame = ttk.Frame(self.decrypt_frame, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File path entry and browse button
        ttk.Label(file_frame, text="File to decrypt:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        self.decrypt_file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.decrypt_file_path, width=60).grid(column=1, row=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_decrypt_file).grid(column=2, row=0, padx=5, pady=5)
        
        # Metadata file path (optional)
        ttk.Label(file_frame, text="Metadata file (optional):").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        self.metadata_file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.metadata_file_path, width=60).grid(column=1, row=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_metadata_file).grid(column=2, row=1, padx=5, pady=5)
        
        # Help text
        help_label = ttk.Label(file_frame, text="Note: If no metadata file is specified, the tool will try to find it automatically based on the encrypted file name.", 
                            wraplength=550, foreground="gray")
        help_label.grid(column=0, row=2, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Decrypt button
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_file, width=15).pack(side=tk.RIGHT, padx=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status text widget
        self.decrypt_status_text = tk.Text(status_frame, height=10, width=70, wrap="word")
        self.decrypt_status_text.pack(fill=tk.BOTH, expand=True)
        self.decrypt_status_text.config(state="disabled")
    
    def create_about_tab(self):
        """Create the about tab with information about the tool"""
        main_frame = ttk.Frame(self.about_frame, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Encryption Tool", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Version
        version_label = ttk.Label(main_frame, text="Version 1.0")
        version_label.pack()
        
        # Description
        desc_frame = ttk.LabelFrame(main_frame, text="Description", padding=10)
        desc_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        description = """
The Advanced Encryption Tool is a desktop application that allows you to encrypt and decrypt 
files using various symmetric encryption algorithms.

Supported algorithms:
- AES (Advanced Encryption Standard)
- DES (Data Encryption Standard)
- 3DES (Triple DES)
- Blowfish
- Twofish
- RC4
- RC6

Features:
- Multiple encryption algorithms
- Default keys or custom passphrase-based keys
- Metadata logging for encrypted files
- User-friendly interface
"""
        
        desc_text = tk.Text(desc_frame, height=15, width=70, wrap="word")
        desc_text.pack(fill=tk.BOTH, expand=True)
        desc_text.insert("1.0", description)
        desc_text.config(state="disabled")
        
        # Footer
        footer_label = ttk.Label(main_frame, text="© 2023 Advanced Encryption Tool")
        footer_label.pack(pady=10)
    
    def toggle_key_options(self):
        """Toggle visibility of key options based on selection"""
        if self.key_option.get() == "default":
            for child in self.default_key_frame.winfo_children():
                child.configure(state="normal")
            for child in self.custom_key_frame.winfo_children():
                child.configure(state="disabled")
        else:
            for child in self.default_key_frame.winfo_children():
                child.configure(state="disabled")
            for child in self.custom_key_frame.winfo_children():
                child.configure(state="normal")
    
    def browse_encrypt_file(self):
        """Open file dialog to select a file to encrypt"""
        filename = filedialog.askopenfilename(title="Select file to encrypt")
        if filename:
            self.encrypt_file_path.set(filename)
    
    def browse_decrypt_file(self):
        """Open file dialog to select a file to decrypt"""
        filename = filedialog.askopenfilename(title="Select file to decrypt")
        if filename:
            self.decrypt_file_path.set(filename)
            # Auto-populate metadata file path
            metadata_path = f"{filename}.txt"
            if os.path.exists(metadata_path):
                self.metadata_file_path.set(metadata_path)
    
    def browse_metadata_file(self):
        """Open file dialog to select a metadata file"""
        filename = filedialog.askopenfilename(title="Select metadata file", 
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.metadata_file_path.set(filename)
    
    def update_status(self, text, is_encrypt=True):
        """Update status text in the appropriate tab"""
        status_text = self.encrypt_status_text if is_encrypt else self.decrypt_status_text
        status_text.config(state="normal")
        status_text.insert(tk.END, f"{text}\n")
        status_text.see(tk.END)
        status_text.config(state="disabled")
        self.status_var.set(text)
    
    def encrypt_file(self):
        """Encrypt the selected file"""
        filepath = self.encrypt_file_path.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return
        
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return
        
        algorithm = self.algorithm_var.get()
        
        # Get key information
        key_option = self.key_option.get()
        if key_option == "default":
            key_index = self.key_index_var.get()
            passphrase = None
        else:  # custom key option
            passphrase = self.passphrase_var.get()
            confirm_passphrase = self.confirm_passphrase_var.get()
            
            if not passphrase:
                messagebox.showerror("Error", "Please enter a passphrase.")
                return
                
            if passphrase != confirm_passphrase:
                messagebox.showerror("Error", "Passphrases do not match.")
                return
                
            key_index = None
        
        # Prompt user for save location
        default_filename = f"encrypted_{os.path.basename(filepath)}"
        output_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension="",
            initialfile=default_filename,
            filetypes=[("All files", "*.*")]
        )
        
        # If user cancels the save dialog, abort encryption
        if not output_path:
            self.update_status("Encryption cancelled by user.")
            return
        
        # Update status before starting encryption
        self.update_status("Starting encryption...")
        self.status_var.set("Encrypting...")
        
        # Run encryption in a separate thread to avoid freezing the GUI
        # Run encryption in a separate thread to avoid freezing the GUI
        def encrypt_thread():
            try:
                result = self.encryption_tool.encrypt_file(
                    filepath, 
                    algorithm=algorithm,
                    key_option=key_option,
                    key_index=key_index,
                    passphrase=passphrase,
                    output_path=output_path
                )
                # Unpack the result tuple
                output_file, metadata_file = result
                self.update_status(f"Encryption completed successfully! Encrypted file saved at: {output_file}")
                self.update_status(f"Metadata file saved at: {metadata_file}")
                self.status_var.set("Encryption completed")
            except Exception as e:
                error_msg = f"Error during encryption: {str(e)}"
                self.update_status(error_msg)
                self.status_var.set("Encryption error")
                messagebox.showerror("Encryption Error", error_msg)
        
        # Start the thread
        thread = threading.Thread(target=encrypt_thread)
        thread.daemon = True
        thread.start()

    def decrypt_file(self):
        """Decrypt the selected file"""
        filepath = self.decrypt_file_path.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return
        
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return
        
        metadata_filepath = self.metadata_file_path.get()
        if metadata_filepath and not os.path.exists(metadata_filepath):
            messagebox.showerror("Error", f"Metadata file not found: {metadata_filepath}")
            return
        
        # Prompt user for save location
        default_filename = f"decrypted_{os.path.basename(filepath).replace('encrypted_', '')}"
        output_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            defaultextension="",
            initialfile=default_filename,
            filetypes=[("All files", "*.*")]
        )
        
        # If user cancels the save dialog, abort decryption
        if not output_path:
            self.update_status("Decryption cancelled by user.", is_encrypt=False)
            return
        
        self.update_status("Starting decryption...", is_encrypt=False)
        self.status_var.set("Decrypting...")
        
        # Run decryption in a separate thread to avoid freezing the GUI
        def decrypt_thread():
            try:
                result = self.encryption_tool.decrypt_file(
                    filepath, 
                    metadata_filepath=metadata_filepath if metadata_filepath else None,
                    output_path=output_path
                )
                
                if result["status"] == "success":
                    self.update_status(f"Decryption completed successfully! Decrypted file saved at: {result['output_file']}", is_encrypt=False)
                    self.status_var.set("Decryption completed")
                else:
                    self.update_status(f"Decryption failed: {result['message']}", is_encrypt=False)
                    self.status_var.set("Decryption failed")
                    messagebox.showerror("Decryption Error", result["message"])
            except Exception as e:
                error_msg = f"Error during decryption: {str(e)}"
                self.update_status(error_msg, is_encrypt=False)
                self.status_var.set("Decryption error")
                messagebox.showerror("Decryption Error", error_msg)
        
        # Start the thread
        thread = threading.Thread(target=decrypt_thread)
        thread.daemon = True
        thread.start()
