import threading
import logging
import os
import keyring  # Add this import
import tkinter as tk
from tkinter import ttk, simpledialog, scrolledtext, messagebox
import paramiko
import ipaddress
import sqlite3
import sys
import bcrypt
from cryptography.fernet import Fernet
from ttkthemes import ThemedTk

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Create a logger
logger = logging.getLogger(__name__)

# Set the logging level
logger.setLevel(logging.INFO)

# Create a file handler and set the formatter
file_handler = logging.FileHandler('update_app.log')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

# Log some messages
# logger.info("This is an info message")
# logger.error("This is an error message")

# Key for encryption (Keep this secret and manage it securely)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

class SecureTextRedirector:
    def __init__(self, text_widget, tag):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, data):
        self.text_widget.config(state="normal")
        self.text_widget.insert(tk.END, data, (self.tag,))
        self.text_widget.see(tk.END)
        self.text_widget.config(state="disabled")


class DatabaseManager:
    def __init__(self, database_name):
        self.conn = sqlite3.connect(database_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_table (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE,
                machine_name TEXT
            )
        ''')
        self.conn.commit()

    def add_ip(self, ip, machine_name):
        try:
            self.cursor.execute("INSERT INTO ip_table (ip, machine_name) VALUES (?, ?)", (ip, machine_name))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.error("Duplicate IP: %s", ip)
            return False

    def edit_ip(self, old_ip, new_ip, new_machine_name):
        try:
            self.cursor.execute("UPDATE ip_table SET ip=?, machine_name=? WHERE ip=?",
                                (new_ip, new_machine_name, old_ip))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            logger.error("Duplicate IP: %s", new_ip)
            return False

    def delete_ip(self, ip):
        try:
            self.cursor.execute("DELETE FROM ip_table WHERE ip=?", (ip,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error("Error deleting IP: %s", e)
            return False

    def get_ips(self):
        self.cursor.execute("SELECT * FROM ip_table")
        return self.cursor.fetchall()


class TextRedirector:
    def __init__(self, text_widget, tag):
        self.text_widget = text_widget
        self.tag = tag

    def write(self, str):
        self.text_widget.config(state="normal")
        self.text_widget.insert(tk.END, str, (self.tag,))
        self.text_widget.see(tk.END)
        self.text_widget.config(state="disabled")


class EditIPDialog(simpledialog.Dialog):
    def __init__(self, parent, title, initial_ip, initial_machine_name):
        self.initial_ip = initial_ip
        self.initial_machine_name = initial_machine_name
        simpledialog.Dialog.__init__(self, parent, title)

    def body(self, master):
        tk.Label(master, text="IP:").grid(row=0, sticky=tk.W)
        tk.Label(master, text="Machine Name:").grid(row=1, sticky=tk.W)

        self.ip_entry = ttk.Entry(master, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_entry.insert(0, self.initial_ip)

        self.machine_name_entry = ttk.Entry(master, width=20)
        self.machine_name_entry.grid(row=1, column=1, padx=5, pady=5)
        self.machine_name_entry.insert(0, self.initial_machine_name)

        return self.ip_entry  # initial focus

    def apply(self):
        new_ip = self.ip_entry.get()
        new_machine_name = self.machine_name_entry.get()
        self.result = new_ip, new_machine_name


class SecureRemoteUpdateApp(ttk.Frame):
    def __init__(self, parent, database_name):
        ttk.Frame.__init__(self, parent)
        self.parent = parent
        self.parent.title("SSh AutoUpdate")
        self.parent.set_theme('plastik')
        self.parent.iconbitmap(resource_path("Logo.ico"))

        self.conn = sqlite3.connect(database_name)
        self.cursor = self.conn.cursor()

        # Encryption for stored information in the database
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

        # Create the IP table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_table (
                id INTEGER PRIMARY KEY,
                ip TEXT UNIQUE,
                machine_name TEXT
            )
        ''')
        self.conn.commit()

        # GUI elements...
        self.setup_gui()

        # Redirect stdout and stderr to the ScrolledText widget
        sys.stdout = SecureTextRedirector(self.output_text, "stdout")
        sys.stderr = SecureTextRedirector(self.output_text, "stderr")

        # Load existing IPs from the database
        self.load_existing_ips()

        # Try to retrieve the SSH username and password from keyring
        stored_username = keyring.get_password("ssh_autoupdate", "username")
        stored_password = keyring.get_password("ssh_autoupdate", "password")

        # If both username and password are stored, set them in the entry boxes
        if stored_username and stored_password:
            self.username_entry.insert(0, stored_username)
            self.password_entry.insert(0, stored_password)

    def run_update_thread(self):
        # Get necessary data from the GUI
        ips = self.ip_listbox.get(0, tk.END)
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Store the SSH username and password securely in keyring
        keyring.set_password("ssh_autoupdate", "username", username)
        keyring.set_password("ssh_autoupdate", "password", password)

        if ips and username and password:
            # Start the update process in a separate thread
            update_thread = threading.Thread(target=self.threaded_update_process, args=(ips, username, password))
            update_thread.start()
        else:
            messagebox.showinfo("Input Error", "Please enter both username and password.")

    def log_message(self, message, level=logging.INFO):
        logger.log(level, message)
        self.output_text.config(state="normal")
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)
        self.output_text.config(state="disabled")

    def setup_gui(self):
        # Create the IP Listbox
        self.ip_listbox = tk.Listbox(self, selectmode=tk.SINGLE)
        self.ip_listbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        # Bind double-click event to edit_ip function
        self.ip_listbox.bind('<Double-1>', lambda event: self.edit_ip())

        # Create the IP Entry
        self.ip_entry = ttk.Entry(self)
        self.ip_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        # Create the Add IP Button
        add_ip_button = ttk.Button(self, text="Add IP", command=self.add_ip)
        add_ip_button.grid(row=1, column=0, padx=10, pady=5, sticky="e")

        # Create the Edit Button
        edit_button = ttk.Button(self, text="Edit IP", command=self.edit_ip)
        edit_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        # Create the Delete Button
        delete_button = ttk.Button(self, text="Delete IP", command=self.delete_ip)
        delete_button.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        # Create the Username Label
        username_label = ttk.Label(self, text="SSH Username:")
        username_label.grid(row=6, column=0, padx=10, pady=5, sticky="w")

        # Create the Password Label
        password_label = ttk.Label(self, text="SSH Password:")
        password_label.grid(row=7, column=0, padx=10, pady=5, sticky="w")

        # Create the Username Entry
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=6, column=0, padx=110, pady=5, sticky="ew")

        # Create the Password Entry
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=7, column=0, padx=110, pady=5, sticky="ew")

        # Create the Go Button
        go_button = ttk.Button(self, text="GO", command=self.run_update_thread)
        go_button.grid(row=8, column=0, padx=10, pady=5, sticky="N")

        # Create the Scrolled Text for application messages
        self.output_text = scrolledtext.ScrolledText(self, wrap="word", state="disabled", height=10)
        self.output_text.grid(row=0, column=1, padx=10, pady=10, sticky="nsew", rowspan=8)

    def add_ip(self):
        ip_input = self.ip_entry.get()
        if ip_input:
            if self.is_valid_ip(ip_input):
                machine_name = simpledialog.askstring("Machine Name", f"Enter machine name for {ip_input}:")
                if machine_name:
                    try:
                        self.cursor.execute("INSERT INTO ip_table (ip, machine_name) VALUES (?, ?)",
                                            (ip_input, machine_name))
                        self.conn.commit()
                        self.ip_listbox.insert(tk.END, f"{ip_input} ({machine_name})")
                        self.ip_entry.delete(0, tk.END)  # Clear the entry after adding
                    except sqlite3.IntegrityError:
                        messagebox.showinfo("Duplicate IP", "IP address already exists in the list.")
                else:
                    messagebox.showinfo("Missing Machine Name", "Please enter a machine name.")
            else:
                messagebox.showinfo("Invalid IP", "Please enter a valid IP address.")

    def edit_ip(self):
        selected_index = self.ip_listbox.curselection()
        if selected_index:
            ip_machine_pair_to_edit = self.ip_listbox.get(selected_index)
            parts = ip_machine_pair_to_edit.split("(")
            initial_ip = parts[0].strip()
            initial_machine_name = parts[1].replace(")", "").strip()

            # Create a custom dialog for editing IP and machine name
            dialog = EditIPDialog(self, "Edit IP and Machine Name", initial_ip, initial_machine_name)
            if dialog.result:
                new_ip, new_machine_name = map(str.strip, dialog.result)

                if self.is_valid_ip(new_ip):
                    try:
                        self.cursor.execute("UPDATE ip_table SET ip=?, machine_name=? WHERE ip=?",
                                            (new_ip, new_machine_name, initial_ip))
                        self.conn.commit()
                        self.ip_listbox.delete(selected_index)
                        self.ip_listbox.insert(tk.END, f"{new_ip} ({new_machine_name})")
                    except sqlite3.IntegrityError:
                        messagebox.showinfo("Duplicate IP", "IP address already exists in the list.")
                else:
                    messagebox.showinfo("Invalid IP", "Please enter a valid IP address.")

    def delete_ip(self):
        selected_index = self.ip_listbox.curselection()
        if selected_index:
            ip_machine_pair_to_delete = self.ip_listbox.get(selected_index)
            parts = ip_machine_pair_to_delete.split("(")
            ip_to_delete = parts[0].strip()

            # Ask for confirmation before deleting
            confirmation = messagebox.askyesno("Confirmation", f"Do you really want to delete {ip_to_delete}?")
            if confirmation:
                try:
                    self.cursor.execute("DELETE FROM ip_table WHERE ip=?", (ip_to_delete,))
                    self.conn.commit()
                    self.ip_listbox.delete(selected_index)
                except Exception as e:
                    messagebox.showinfo("Error", f"Error deleting IP: {e}")

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def load_existing_ips(self):
        self.ip_listbox.delete(0, tk.END)
        self.cursor.execute("SELECT * FROM ip_table")
        ips = self.cursor.fetchall()
        for ip in ips:
            ip_machine_pair = f"{ip[1]} ({ip[2]})"
            self.ip_listbox.insert(tk.END, ip_machine_pair)

    def threaded_update_process(self, ips, username, password):
        """
        Update remote machines using SSH.
        Args:
            ips (list): List of IP and machine_name pairs.
            username (str): SSH username.
            password (str): SSH password.
        """
        for ip_machine_pair in ips:
            ip, machine_name = self.extract_ip_machine_pair(ip_machine_pair)

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=5)

                # Log when the update process starts
                self.log_message(f"Update started on {machine_name} ({ip})")

                stdin, stdout, stderr = ssh.exec_command("sudo apt update && sudo apt upgrade -y")
                for line in stdout:
                    self.log_message(f"{machine_name} ({ip}) - {line.strip()}")
                for line in stderr:
                    self.log_message(f"{machine_name} ({ip}) - {line.strip()}", level=logging.ERROR)

                # Log when the update process finishes successfully
                self.log_message(f"Update finished successfully on {machine_name} ({ip})")

                ssh.close()
            except Exception as e:
                # Log errors and continue the loop
                self.log_message(f"{machine_name} ({ip}) - Error updating: {e}", level=logging.ERROR)
                continue

        # Log when the entire update process finishes
        self.log_message("Update process completed")

    # Add this helper function to extract ip and machine_name
    def extract_ip_machine_pair(self, ip_machine_pair):
        parts = ip_machine_pair.split("(")
        if len(parts) > 1:
            ip = parts[0].strip()
            machine_name = parts[1].replace(")", "").strip()
            return ip, machine_name
        else:
            return "", ""

    def run_update_process(self):
        ips = self.ip_listbox.get(0, tk.END)
        if ips:
            username = self.get_secure_input("SSH Username:")
            password = self.get_secure_password("SSH Password:")

            if username and password:
                for ip_machine_pair in ips:
                    ip, machine_name = self.extract_ip_machine_pair(ip_machine_pair)
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                        # Decrypt password before using it
                        decrypted_password = self.decrypt_data(password)

                        ssh.connect(ip, username=username, password=decrypted_password, timeout=5)

                        stdin, stdout, stderr = ssh.exec_command("sudo apt update && sudo apt upgrade -y")
                        for line in stdout:
                            print(f"{machine_name} ({ip}) - {line.strip()}")
                        for line in stderr:
                            print(f"{machine_name} ({ip}) - {line.strip()}")

                        ssh.close()
                        print(f"Update executed successfully on {machine_name} ({ip})")
                    except Exception as e:
                        print(f"{machine_name} ({ip}) - Error updating: {e}")
                        continue
            else:
                messagebox.showinfo("SSH Authentication", "Please enter both username and password.")

    def get_secure_input(self, prompt):
        return simpledialog.askstring(prompt, f"Enter {prompt.lower()}:")

    def get_secure_password(self, prompt):
        password = simpledialog.askstring(prompt, f"Enter {prompt.lower()}:", show='*')
        # Encrypt the password before storing it
        return self.encrypt_data(password)

    def encrypt_data(self, data):
        return self.cipher_suite.encrypt(data.encode('utf-8'))

    def decrypt_data(self, encrypted_data):
        return self.cipher_suite.decrypt(encrypted_data).decode('utf-8')


def threaded_update_process(ips, username, password):
    for ip_machine_pair in ips:
        ip, machine_name = ip_machine_pair
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command("sudo apt update && sudo apt upgrade -y")
            for line in stdout:
                print(f"{machine_name} ({ip}) - {line.strip()}")  # Print output in real-time with machine IP
            for line in stderr:
                print(f"{machine_name} ({ip}) - {line.strip()}")  # Print error in real-time with machine IP
            ssh.close()
            print(f"Update executed successfully on {machine_name} ({ip})")
        except Exception as e:
            print(f"{machine_name} ({ip}) - Error updating: {e}")
            continue


if __name__ == "__main__":
    root = ThemedTk(theme="plastik")
    root.resizable(False, False)

    db_manager = DatabaseManager(database_name="ip_database.db")
    app = SecureRemoteUpdateApp(root, database_name="ip_database.db")
    app.pack(fill="both", expand=True)

    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())
    x_coordinate = int((root.winfo_screenwidth() / 2) - (root.winfo_width() / 2))
    y_coordinate = int((root.winfo_screenheight() / 2) - (root.winfo_height() / 2))
    root.geometry("+{}+{}".format(x_coordinate, y_coordinate))

    root.mainloop()
