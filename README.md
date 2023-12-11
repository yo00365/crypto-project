# Secure Email Web Application

## Overview

The Secure Email Web Application is a Flask-based web application designed to provide a secure platform for email communication between registered users. It emphasizes user authentication, password security, and encryption techniques to ensure the confidentiality of email messages.

## Table of Contents

- [Features](#features)
- [Usage](#usage)
- [Security](#security)
- [Installation](#installation)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

### 1. Flask Web Application

- The code implements a web application using Flask, a lightweight Python web framework.

### 2. User Authentication

- User authentication is managed using Flask-Login, providing a secure way to handle user sessions.

### 3. Password Hashing

- User passwords are securely hashed using Werkzeug's `generate_password_hash` function.

### 4. Public Key Infrastructure (PKI)

- RSA key pairs are generated for each user during the registration process.
- Public keys are stored in the user database for secure email communication.

### 5. Email Encryption

- Users can send and receive encrypted emails.
- Symmetric key cryptography (AES) is used to encrypt email messages securely.

### 6. File Storage

- User data, including hashed passwords and public keys, is stored in a JSON file (`users.json`).
- Sent and received emails are stored in a text file (`emails_db.txt`).

### 7. Route Definitions

- Routes are defined for user registration, login, logout, sending emails, and viewing received emails.

### 8. Redirects

- After successful registration, users are redirected to the login page.
- After successful login, users are redirected to the send_email page.

### 9. Error Handling

- The code handles cases where usernames are already taken during registration and provides feedback to the user.

### 10. Random Generation

- Cryptographically secure random bytes are generated using `get_random_bytes`.

### 11. Web Templates

- HTML templates are used for rendering user interfaces, making use of Jinja templating in Flask.

### 12. Dynamic Content Rendering

- Templates dynamically render content based on the user's authentication status.

### 13. Logout Functionality

- Users can log out securely using the `/logout` route.

### 14. Debug Mode

- The application runs in debug mode, providing detailed error messages during development.

### 15. Exception Handling

- Exception handling is implemented for file loading and user data retrieval.

## Usage

### Registration

1. Users can register with a unique username and a secure password.
2. RSA key pairs are generated for each user, enhancing the security of email communication.

### Login

1. Registered users can securely log in using their credentials.
2. Upon successful login, users are redirected to the "Send Email" page.

### Send Email

1. Authenticated users can compose and send encrypted emails.
2. The recipient's public key is used for secure key exchange and email encryption.

### Receive Emails

1. Users can view a list of received emails, decrypted and displayed in a user-friendly format.

### Logout

1. Users can log out of their sessions securely, ensuring the protection of sensitive information.

## Security

### Password Hashing (Security of User Credentials)

- The SHA-256 algorithm is used to hash user passwords during registration.
- Password hashing prevents exposure of plaintext passwords in case of a data breach.

### RSA Key Pair Generation (Secure Email Encryption)

- Each user is assigned a unique RSA key pair during registration.
- RSA key pairs play a pivotal role in email encryption, ensuring the confidentiality of messages.

### AES Symmetric Key Encryption (Secure Email Content)

- Symmetric key cryptography using the AES algorithm is employed to encrypt the content of email messages.
- AES provides a fast and secure method for encrypting large amounts of data.

### Flask-Login Integration (Session Management)

- Flask-Login is used for managing user sessions, preventing unauthorized access to protected routes.

### File Storage and Data Persistence (User Data Security)

- User data, including hashed passwords and public keys, is stored securely.
- Secure storage of user data is crucial for persistent user experiences.

### Error Handling and Feedback (User Input Security)

- Proper error handling enhances user experience and prevents potential security risks.

### Random Generation (Cryptographically Secure Randomness)

- Cryptographically secure randomness is used for generating unpredictable keys.

### Exception Handling (Data Loading and Retrieval)

- Exception handling is implemented for file operations, ensuring predictable behavior.

## Installation

To install and run the Secure Email Web Application locally, follow these steps:

1. Clone the repository: `git clone [repository_url]`
2. Navigate to the project directory: `cd secure-email-web-app`
3. Install dependencies: `pip install -r requirements.txt`
4. Run the application: `python app.py`

## Testing

Execute planned test activities to ensure the reliability, security, and user satisfaction of the Secure Email Web Application. Refer to the [Planned Testing Activities](#planned-testing-activities) section for detailed instructions.

## Contributing

Contributions to the Secure Email Web Application are welcome! Fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

---

Feel free to modify the sections based on your project's specific details and requirements.
