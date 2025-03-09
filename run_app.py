import tkinter as tk
from encryption_desktop_app import AdvancedEncryptionToolGUI  # Updated class name

def main():
    # Create the root window
    root = tk.Tk()
    root.title("Encryption Desktop Application")
    
    # Initialize the application
    app = AdvancedEncryptionToolGUI(root)
    
    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()

