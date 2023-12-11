from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure, random value

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

USERS_FILE = 'users.json'
EMAILS_FILE = 'emails_db.txt'

# User class for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        user = User()
        user.id = user_id
        return user
    return None

# Load existing user data
try:
    with open(USERS_FILE, 'r') as file:
        users = json.load(file)
except FileNotFoundError:
    users = {}

def save_users():
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file)

def save_emails(emails):
    with open(EMAILS_FILE, 'w') as file:
        json.dump(emails, file)

def load_emails():
    try:
        with open(EMAILS_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return "Username already taken. Please choose another username."

        hashed_password = generate_password_hash(password, method='sha256')

        key = RSA.generate(2048)
        public_key = key.publickey().export_key().decode('utf-8')

        users[username] = {
            'password': hashed_password,
            'public_key': public_key
        }
        save_users()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username]['password'], password):
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('send_email'))
        else:
            return "Login failed. Please check your username and password."

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/send_email')
@login_required
def send_email():
    return render_template('send.html', public_key=users[current_user.id]['public_key'])

@app.route('/send', methods=['POST'])
@login_required
def send():
    to = request.form['to'].strip()
    subject = request.form['subject']
    message = request.form['message']

    if to not in users:
        return "Recipient not found."

    symmetric_key = get_random_bytes(16)
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

    recipient_key = RSA.import_key(users[to]['public_key'])
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)

    emails = load_emails()
    emails.append({
        'sender': current_user.id,
        'recipient': to,
        'subject': subject,
        'body': message,
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
    })
    save_emails(emails)

    return redirect(url_for('send_email'))

@app.route('/received_emails')
@login_required
def received_emails_page():
    emails = load_emails()
    received_emails = [email for email in emails if email['recipient'] == current_user.id]
    return render_template('received.html', received_emails=received_emails)

if __name__ == '__main__':
    app.run(debug=True)
