import os
import hashlib
import time
import mimetypes
import subprocess
import base64
import stat
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext, ttk
from cryptography.fernet import Fernet

# ===============================
# FILE PATH SETUP
# ===============================
# Targets your specific OneDrive folder
BASE_FOLDER = os.path.join(os.environ.get("OneDrive", ""), "ProgrammingCourseWork")

if not os.path.exists(BASE_FOLDER):
    os.makedirs(BASE_FOLDER, exist_ok=True)

# Standard paths for ClamAV installation
CLAMAV_PATH = r"C:\Program Files\ClamAV\clamscan.exe"
CLAMAV_DB = r"C:\ProgramData\ClamAV"
selected_file = None

# ===============================
# MAIN CODE
# ===============================

def generate_key(password):
    """Creates a secure encryption key from a plain text password."""
    hashed = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def set_loading(is_loading):
    """Shows or hides a loading message to the user."""
    if is_loading:
        loading_label.config(text="Processing... Please wait...", fg="orange")
        root.update_idletasks()
    else:
        loading_label.config(text="Ready", fg="green")

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    if selected_file:
        file_info_label.config(text=f"Selected: {os.path.basename(selected_file)}")
        # Clear screens for new file
        meta_display.delete(1.0, tk.END)
        scan_display.delete(1.0, tk.END)

def analyze_metadata():
    if not selected_file:
        messagebox.showwarning("Warning", "Please select a file first.")
        return
    
    set_loading(True)
    time.sleep(0.5) # Small delay to make loading visible for the project demo
    
    meta_display.delete(1.0, tk.END)
    stats = os.stat(selected_file)
    
    # Detailed metadata collection
    info = [
        f"FILE NAME: {os.path.basename(selected_file)}",
        f"EXTENSION: {os.path.splitext(selected_file)[1]}",
        f"SIZE: {stats.st_size} bytes",
        f"MIME TYPE: {mimetypes.guess_type(selected_file)[0] or 'Unknown'}",
        f"PERMISSIONS: {stat.filemode(stats.st_mode)}",
        f"LAST ACCESSED: {time.ctime(stats.st_atime)}",
        f"LAST MODIFIED: {time.ctime(stats.st_mtime)}",
        f"CREATED: {time.ctime(stats.st_ctime)}",
        f"\nDIGITAL SIGNATURE (SHA-256):",
        hashlib.sha256(open(selected_file, "rb").read()).hexdigest()
    ]
    
    meta_display.insert(tk.END, "\n".join(info))
    set_loading(False)
    notebook.select(0) # Switch to Metadata tab

def run_antivirus():
    if not selected_file:
        messagebox.showwarning("Warning", "Select a file first.")
        return
    
    set_loading(True)
    scan_display.delete(1.0, tk.END)
    
    try:
        # Run ClamAV command
        cmd = f'"{CLAMAV_PATH}" --database="{CLAMAV_DB}" "{selected_file}"'
        result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, shell=True)
        
        # Filter: Remove the redundant path line ending in OK
        lines = result.stdout.splitlines()
        clean_output = [l for l in lines if not l.strip().endswith(": OK")]
        
        scan_display.insert(tk.END, "\n".join(clean_output))
    except Exception as e:
        scan_display.insert(tk.END, f"Error: Could not run scan. {e}")
    
    set_loading(False)
    notebook.select(1) # Switch to Antivirus tab

def encrypt_file():
    if not selected_file: return
    pwd = simpledialog.askstring("Password", "Set encryption password:", show="*")
    if not pwd: return
    
    try:
        key = generate_key(pwd)
        f = Fernet(key)
        with open(selected_file, "rb") as file:
            encrypted_data = f.encrypt(file.read())
        
        # Save to ProgrammingCourseWork folder
        output_name = os.path.basename(selected_file) + ".enc"
        output_path = os.path.join(BASE_FOLDER, output_name)
        
        with open(output_path, "wb") as file:
            file.write(encrypted_data)
        messagebox.showinfo("Success", "File encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file():
    if not selected_file or not selected_file.endswith(".enc"):
        messagebox.showerror("Error", "Please select a .enc file.")
        return
    pwd = simpledialog.askstring("Password", "Enter decryption password:", show="*")
    if not pwd: return
    
    try:
        key = generate_key(pwd)
        f = Fernet(key)
        with open(selected_file, "rb") as file:
            decrypted_data = f.decrypt(file.read())
        
        # Restore original extension
        original_name = os.path.basename(selected_file).replace(".enc", "")
        output_path = os.path.join(BASE_FOLDER, original_name)
        
        with open(output_path, "wb") as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted and restored.")
    except:
        messagebox.showerror("Error", "Incorrect password.")

# ===============================
# GUI LAYOUT
# ===============================
root = tk.Tk()
root.title("Vault Guard - School Project")
root.geometry("800x750")
root.configure(bg="white")

# Top Branding
header = tk.Frame(root, bg="#004d40", height=80) # Dark Teal header
header.pack(fill="x")
tk.Label(header, text="Secure File Manager", fg="white", bg="#004d40", font=("Arial", 16, "bold")).pack(pady=20)

# File Selection Card
card_frame = tk.Frame(root, bg="white", highlightbackground="#e0e0e0", highlightthickness=1)
card_frame.pack(pady=20, padx=50, fill="x")

tk.Button(card_frame, text="Select File", command=select_file, bg="#00796b", fg="white", relief="flat", padx=20).pack(pady=10)
file_info_label = tk.Label(card_frame, text="No file selected", bg="white", font=("Arial", 9))
file_info_label.pack(pady=5)

# Loading Status [New Feature]
loading_label = tk.Label(root, text="Ready", font=("Arial", 10, "bold"), bg="white", fg="green")
loading_label.pack()

# Tabbed Results Area
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill="both", padx=50, pady=10)

tab1 = tk.Frame(notebook, bg="white")
meta_display = scrolledtext.ScrolledText(tab1, height=12, font=("Consolas", 10), bg="#f9f9f9")
meta_display.pack(expand=True, fill="both", padx=10, pady=10)
notebook.add(tab1, text="  Metadata Viewer  ")

tab2 = tk.Frame(notebook, bg="white")
scan_display = scrolledtext.ScrolledText(tab2, height=12, font=("Consolas", 10), bg="#f9f9f9")
scan_display.pack(expand=True, fill="both", padx=10, pady=10)
notebook.add(tab2, text="  Antivirus Scan  ")

# Footer Buttons
footer = tk.Frame(root, bg="white")
footer.pack(pady=20)

btn_opts = {"width": 15, "relief": "flat", "font": ("Arial", 10, "bold"), "pady": 8}
tk.Button(footer, text="View Metadata", command=analyze_metadata, bg="#e0e0e0", **btn_opts).grid(row=0, column=0, padx=5)
tk.Button(footer, text="Run Scan", command=run_antivirus, bg="#e0e0e0", **btn_style if 'btn_style' in locals() else btn_opts).grid(row=0, column=1, padx=5)
tk.Button(footer, text="Encrypt File", command=encrypt_file, bg="#43a047", fg="white", **btn_opts).grid(row=0, column=2, padx=5)
tk.Button(footer, text="Decrypt File", command=decrypt_file, bg="#e53935", fg="white", **btn_opts).grid(row=0, column=3, padx=5)

root.mainloop()