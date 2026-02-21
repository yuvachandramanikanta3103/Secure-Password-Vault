# Secure Password Vault

Desktop application to securely store account passwords using AES encryption and bcrypt hashed master password.

## Files
- `main.py` : Main Tkinter GUI application.
- `db.py` : Database helper functions (SQLite).
- `crypto.py` : Encryption/decryption helpers using Fernet (AES) and key derivation.
- `requirements.txt` : Python package dependencies.
- `README.md` : This file.

## How to run
1. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # macOS/Linux
   venv\Scripts\activate    # Windows
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python main.py
   ```

## Notes
- On first run you'll be asked to create a master password. That password is hashed with bcrypt and stored in the SQLite database (`vault.db`).
- Account passwords are encrypted using a symmetric key derived from the master password (PBKDF2HMAC -> Fernet key). The encrypted blob is stored in the database.
- Export to CSV will write encrypted passwords by default. You can modify the export function to export plaintext (not recommended).
- Keep the `vault.db` file safe. If you lose the master password there is no way to recover the encrypted data.
