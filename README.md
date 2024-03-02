# Secure SSH AutoUpdate
![SSh AuditUpdate](https://github.com/cruzcg/SSh-AutoUpdate/assets/64936909/72f389a4-b128-4e96-a26b-bb44feb4ac7c)


Secure SSH AutoUpdate is a Python application designed to securely update remote machines using SSH. It provides a user-friendly GUI for managing IP addresses, SSH credentials, and initiating the update process.

## Features

- **Secure Storage:** Utilizes encryption for storing sensitive information such as SSH passwords.
- **IP Management:** Add, edit, and delete IP addresses along with corresponding machine names.
- **Real-time Logging:** View real-time updates and errors during the SSH update process.
- **Threading:** Ensures the GUI remains responsive during the background update process.
- **SQLite Database:** Manages IP addresses and machine names using a SQLite database.

## Setup

1. **Dependencies:**
   - Ensure you have Python installed (version 3.6 or higher).
   - Install required packages using:
     ```bash
     pip install paramiko ipaddress bcrypt cryptography ttkthemes
     ```

2. **Run the Application:**
   - Execute the following command in the terminal:
     ```bash
     python secure_ssh_autoupdate.py
     ```

## Usage

1. **Add IP Addresses:**
   - Open the application and click on the "Add IP" button.
   - Enter the IP address and provide a machine name.

2. **Edit IP Addresses:**
   - Double-click on an IP address in the list to edit it.
   - Modify the IP address or machine name as needed.

3. **Delete IP Addresses:**
   - Select an IP address and click on the "Delete IP" button to remove it.

4. **Update Remote Machines:**
   - Enter SSH username and password.
   - Click on the "GO" button to initiate the update process.

5. **Real-time Logging:**
   - View updates and errors in the ScrolledText widget in real-time.

## Contributions

Contributions to enhance the functionality, fix bugs, or improve the user interface are welcome! Follow the steps below to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push the branch to your fork.
4. Open a pull request with a clear description of your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

