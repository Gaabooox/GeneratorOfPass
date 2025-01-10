# KeyPass

This program allows you to encrypt and decrypt files. In addition, you can automatically generate secure passwords.

## Requirements

- Python 3.x
- Libraries:
- `cryptography`
- `pyperclip`

To install the necessary libraries, you can use the following command:

```bash
pip install cryptography pyperclip
```

## Functionalities

The program offers the following options:

- Encrypt file: Encrypts a file with a provided password.
- Decrypt file: Decrypts a file previously encrypted with the correct password.
- Generate secure password: Generates a random secure password of the length you choose and copies it to the clipboard.
- Exit: Ends the execution of the program.

## How to use the program

Run the Python script: Open a terminal in the directory where the keypass.py file is located and run the following command:

```bash
python keypass.py
```

- Select an option: The program will present you with a menu with the options mentioned above. Enter the number of the option you want to use.

- Option 1: Encrypt file
  Select option 1 to encrypt a file.
  You will be asked to enter the name of the file you want to encrypt.
  Then, you will need to enter a password to encrypt the file.
- Option 2: Decrypt file
  Select option 2 to decrypt a file.
  You will be asked to enter the name of the encrypted file.
  Then, you will need to enter the password to decrypt the file.
- Option 4: Generate secure password
  Select option 4 to generate a secure password.
  You will be prompted to enter the password length (minimum 10 characters).
  The generated password will be automatically copied to the clipboard for you to use.
- Option 5: Exit
  Select option 5 to exit the program.
