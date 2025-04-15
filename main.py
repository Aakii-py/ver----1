import os
import json
import base64
import csv
import re
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

DATA_FILE = "data.json"
SALT_FILE = "password.key"

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ================== ENCRYPTION HELPERS ==================
def generate_salt():
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as sf:
        sf.write(salt)
    print(f"Generated new salt: {salt}")
    return salt

def load_salt():
    if not os.path.exists(SALT_FILE):
        print("Salt file not found, generating new salt.")
        return generate_salt()
    with open(SALT_FILE, "rb") as sf:
        return sf.read()

def derive_key(password: str, salt: bytes) -> bytes:
    print(f"Deriving key using password: {password}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    derived_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    print(f"Derived key: {derived_key}")
    return derived_key

def encrypt_message(message: str, fernet: Fernet) -> str:
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(token: str, fernet: Fernet) -> str:
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return "<DECRYPTION FAILED>"

# ================== CORE FUNCTIONALITY ==================
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as file:
        return json.load(file)

def save_data(data):
    try:
        with open(DATA_FILE, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Data saved to {DATA_FILE}")
    except IOError as e:
        print(f"Error saving data to {DATA_FILE}: {e}")

def import_from_csv(file_path, data, fernet_instance):
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                service = row.get('name') or row.get('url') or 'Unnamed'
                username = row.get('username', '')
                password = row.get('password', '')

                if not username or not password:
                    continue

                encrypted_username = encrypt_message(username, fernet_instance)
                encrypted_password = encrypt_message(password, fernet_instance)

                data[service] = {
                    "username_encrypted": encrypted_username,
                    "password_encrypted": encrypted_password
                }
        return data
    except Exception as e:
        print(f"Error importing CSV: {e}")
        return data

# ================== GUI APP ==================
class PasswordVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Password Vault")
        self.geometry("600x500")
        self.data = {}
        self.fernet = None
        self.create_login_screen()

    def create_login_screen(self):
        self.clear_widgets()
        self.label = ctk.CTkLabel(self, text="Enter Master Password", font=("Segoe UI", 20))
        self.label.pack(pady=30)

        self.password_entry = ctk.CTkEntry(self, show="*", width=300)
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(self, text="Login", command=self.login)
        self.login_button.pack(pady=20)

    def login(self):
        password = self.password_entry.get()
        print(f"User entered password: {password}")
        salt = load_salt()
        try:
            key = derive_key(password, salt)
            self.fernet = Fernet(key)
            self.data = load_data()
            print(f"Data loaded: {self.data}")
            self.create_main_screen()
        except Exception as e:
            print(f"Error during login: {e}")
            messagebox.showerror("Error", "Incorrect password or key issue.")

    def create_main_screen(self):
        self.clear_widgets()
        ctk.CTkLabel(self, text="Password Vault", font=("Segoe UI", 22, "bold")).pack(pady=15)

        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=10, fill="both", expand=True)

        self.listbox = ctk.CTkTextbox(self.frame, wrap="none", height=200)
        self.listbox.pack(fill="both", padx=10, pady=10, expand=True)

        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=10)

        ctk.CTkButton(btn_frame, text="View Entries", command=self.view_entries).grid(row=0, column=0, padx=5)
        ctk.CTkButton(btn_frame, text="Add Entry", command=self.add_entry_popup).grid(row=0, column=1, padx=5)
        ctk.CTkButton(btn_frame, text="Search", command=self.open_search_popup).grid(row=0, column=2, padx=5)
        ctk.CTkButton(btn_frame, text="Import CSV", command=self.import_csv).grid(row=0, column=3, padx=5)
        ctk.CTkButton(btn_frame, text="Save", command=self.save_all).grid(row=0, column=4, padx=5)

        self.view_entries()

    def view_entries(self):
        self.listbox.delete("1.0", "end")
        for service, creds in self.data.items():
            decrypted_username = decrypt_message(creds["username_encrypted"], self.fernet)
            decrypted_password = decrypt_message(creds["password_encrypted"], self.fernet)
            self.listbox.insert("end", f"🔐 {service}\n  👤 {decrypted_username}\n  🔑 {decrypted_password}\n------------------------\n")

    def add_entry_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Add New Entry")
        popup.geometry("300x250")

        ctk.CTkLabel(popup, text="Service Name").pack(pady=5)
        service_entry = ctk.CTkEntry(popup)
        service_entry.pack(pady=5)

        ctk.CTkLabel(popup, text="Username").pack(pady=5)
        username_entry = ctk.CTkEntry(popup)
        username_entry.pack(pady=5)

        ctk.CTkLabel(popup, text="Password").pack(pady=5)
        password_entry = ctk.CTkEntry(popup)
        password_entry.pack(pady=5)

        def save():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if service and username and password:
                self.data[service] = {
                    "username_encrypted": encrypt_message(username, self.fernet),
                    "password_encrypted": encrypt_message(password, self.fernet)
                }
                popup.destroy()
                self.view_entries()

        ctk.CTkButton(popup, text="Save", command=save).pack(pady=10)

    def open_search_popup(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Search Entries")
        popup.geometry("300x150")

        ctk.CTkLabel(popup, text="Enter regex to search:").pack(pady=5)
        search_entry_field = ctk.CTkEntry(popup, width=250)
        search_entry_field.pack(pady=10)

        def search():
            query = search_entry_field.get()
            self.search_entry(query)

        ctk.CTkButton(popup, text="Search", command=search).pack(pady=10)

    def search_entry(self, query):
        if not query:
            messagebox.showerror("Error", "Search query cannot be empty.")
            return

        self.listbox.delete("1.0", "end")
        found = False
        try:
            pattern = re.compile(query, re.IGNORECASE)
        except re.error as e:
            pattern = None

        for service, credentials in self.data.items():
            decrypted_username = decrypt_message(credentials.get("username_encrypted", ""), self.fernet)
            service_match = pattern.search(service) if pattern else query.lower() in service.lower()
            username_match = pattern.search(decrypted_username) if pattern else query.lower() in decrypted_username.lower()

            if service_match or username_match:
                found = True
                decrypted_password = decrypt_message(credentials.get("password_encrypted", ""), self.fernet)
                self.listbox.insert("end", f"\n🔍 Match found: {service}\n  Username: {decrypted_username}\n  Password: {decrypted_password}\n------------------------\n")

        if not found:
            self.listbox.insert("end", "No matching service or username found.")

    def import_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if path:
            import_from_csv(path, self.data, self.fernet)
            self.view_entries()

    def save_all(self):
        save_data(self.data)
        messagebox.showinfo("Saved", "Data saved successfully!")

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = PasswordVaultApp()
    app.mainloop()
