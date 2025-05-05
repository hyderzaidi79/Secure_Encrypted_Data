# Secure Encrypted Data Vault

This is a Streamlit-based web application that allows users to securely store and retrieve encrypted data. It uses AES encryption with the help of the `cryptography` package and provides secure user authentication with hashed passwords and a login attempt limit to protect against brute-force attacks.

## Features

- **User Registration & Login:** Allows users to create an account and log in securely.
- **Data Encryption:** Users can store and encrypt sensitive data with a passkey using AES encryption.
- **Decryption:** Users can retrieve their encrypted data by entering the correct passkey.
- **Failed Login Attempts Tracking:** Protects accounts from brute-force attacks by locking the account after 3 failed login attempts within 60 seconds.
- **Export Data:** Users can export their encrypted data as a JSON file.
- **Secure Storage:** All user data, including encrypted content and passkeys, is securely stored and never exposed in plain text.

## Requirements

Before you begin, ensure you have the following installed:

- Python 3.x
- `cryptography` library
- `streamlit` library

### Installing Dependencies

1. Install the required Python packages using `pip`:

```bash
pip install cryptography streamlit

How to Run

    Clone this repository or download the code files.

    Ensure that all dependencies are installed.

    Run the Streamlit app by executing the following command:

streamlit run app.py

    Open the app in your browser (typically at http://localhost:8501).

File Overview

    app.py: The main Python script that runs the Streamlit app and handles the user interface, data encryption, and decryption logic.

    secret.key: The file that stores the encryption key (generated once and reused for encryption/decryption).

    users.json: The file where user credentials (hashed passwords) are stored.

    data_store.json: The file that holds the encrypted data for each user.

    login_attempts.json: The file that tracks the login attempts for each user to protect against brute-force attacks.

Features and UI Walkthrough
Home Page

    Welcome message and the option to navigate to login, registration, and data storage pages.

Register Page

    Allows users to create a new account by providing a username and password.

Login Page

    Users log in by providing their username and password. If too many failed login attempts are made, the account will be temporarily locked.

Store Data Page

    After logging in, users can securely store encrypted data. The data is encrypted using a passkey provided by the user.

Retrieve Data Page

    Users can retrieve previously stored encrypted data by entering the correct encrypted text and passkey.

Export Data Page

    Users can download their encrypted data in JSON format.

Security Considerations

    Passwords are hashed using SHA-256 to ensure that they are not stored in plain text.

    The encryption key is securely stored in a file (secret.key) and is used for both encryption and decryption processes.

    Failed login attempts are tracked, and accounts are temporarily locked after multiple failed attempts, adding an extra layer of security against brute-force attacks.

License

This project is licensed under the MIT License.


This README includes a description of the project, installation instructions, and how to use the app. It also explains the security features and provides a file overview.

