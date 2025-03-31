from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
import re
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# Database connection function
def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Encryption setup
def get_encryption_key():
    key = os.getenv('ENCRYPTION_KEY').encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(key))
    return Fernet(key)

def encrypt_data(data):
    if not data:
        return None
    fernet = get_encryption_key()
    return fernet.encrypt(str(data).encode()).decode()

def decrypt_data(encrypted_data):
    if not encrypted_data:
        return None
    fernet = get_encryption_key()
    return fernet.decrypt(encrypted_data.encode()).decode()

# User class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data[0]
        self.username = user_data[1]
        self.email = decrypt_data(user_data[2])
        self.account_id = decrypt_data(user_data[4])
        self.balance = float(user_data[5])

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(user_data)
        finally:
            cursor.close()
            connection.close()
    return None

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Template Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    
    if not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        
        # Check if username exists
        cursor.execute("SELECT id FROM users WHERE username = %s", (data['username'],))
        if cursor.fetchone():
            return jsonify({'error': 'Username already exists'}), 400
        
        # Check if email exists
        encrypted_email = encrypt_data(data['email'])
        cursor.execute("SELECT id FROM users WHERE email = %s", (encrypted_email,))
        if cursor.fetchone():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Generate account ID and hash password
        account_id = f"ACC{datetime.now().strftime('%Y%m%d%H%M%S')}"
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        encrypted_account_id = encrypt_data(account_id)
        
        # Insert new user
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, account_id, balance)
            VALUES (%s, %s, %s, %s, %s)
        """, (data['username'], encrypted_email, hashed_password, encrypted_account_id, 0.0))
        
        connection.commit()
        return jsonify({
            'message': 'Registration successful',
            'account_id': account_id
        }), 201
        
    except Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    
    if not all(key in data for key in ['username', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400
    
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (data['username'],))
        user_data = cursor.fetchone()
        
        if user_data and bcrypt.check_password_hash(user_data[3], data['password']):
            user = User(user_data)
            login_user(user)
            return jsonify({'message': 'Login successful'}), 200
        
        return jsonify({'error': 'Invalid username or password'}), 401
    finally:
        cursor.close()
        connection.close()

@app.route('/api/balance', methods=['GET'])
@login_required
def api_balance():
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT account_id, balance FROM users WHERE id = %s", (current_user.id,))
        encrypted_account_id, balance = cursor.fetchone()
        
        return jsonify({
            'account_id': decrypt_data(encrypted_account_id),
            'balance': float(balance)
        }), 200
    finally:
        cursor.close()
        connection.close()

@app.route('/api/statement', methods=['GET'])
@login_required
def api_statement():
    connection = get_db_connection()
    if not connection:
        return jsonify({'error': 'Database connection error'}), 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT transaction_type, amount, balance_after, timestamp
            FROM transactions
            WHERE user_id = %s
            ORDER BY timestamp DESC
        """, (current_user.id,))
        
        transactions = [{
            'transaction_type': decrypt_data(t[0]),
            'amount': float(t[1]),
            'balance_after': float(t[2]),
            'timestamp': t[3].strftime('%Y-%m-%d %H:%M:%S')
        } for t in cursor.fetchall()]
        
        return jsonify({
            'transactions': transactions
        }), 200
    finally:
        cursor.close()
        connection.close()

@app.route('/api/deposit', methods=['POST'])
@login_required
def api_deposit():
    data = request.get_json()
    
    if 'amount' not in data:
        return jsonify({'error': 'Amount is required'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'error': 'Database connection error'}), 500
        
        try:
            cursor = connection.cursor()
            
            # Update user balance
            cursor.execute("""
                UPDATE users SET balance = balance + %s WHERE id = %s
            """, (amount, current_user.id))
            
            # Get new balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            new_balance = cursor.fetchone()[0]
            
            # Record transaction
            cursor.execute("""
                INSERT INTO transactions (user_id, transaction_type, amount, balance_after)
                VALUES (%s, %s, %s, %s)
            """, (current_user.id, encrypt_data('deposit'), amount, new_balance))
            
            connection.commit()
            
            return jsonify({
                'message': 'Deposit successful',
                'new_balance': float(new_balance)
            }), 200
            
        finally:
            cursor.close()
            connection.close()
            
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

@app.route('/api/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    data = request.get_json()
    
    if 'amount' not in data:
        return jsonify({'error': 'Amount is required'}), 400
    
    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        
        connection = get_db_connection()
        if not connection:
            return jsonify({'error': 'Database connection error'}), 500
        
        try:
            cursor = connection.cursor()
            
            # Check balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            current_balance = cursor.fetchone()[0]
            
            if amount > float(current_balance):
                return jsonify({'error': 'Insufficient funds'}), 400
            
            # Update user balance
            cursor.execute("""
                UPDATE users SET balance = balance - %s WHERE id = %s
            """, (amount, current_user.id))
            
            # Get new balance
            cursor.execute("SELECT balance FROM users WHERE id = %s", (current_user.id,))
            new_balance = cursor.fetchone()[0]
            
            # Record transaction
            cursor.execute("""
                INSERT INTO transactions (user_id, transaction_type, amount, balance_after)
                VALUES (%s, %s, %s, %s)
            """, (current_user.id, encrypt_data('withdrawal'), amount, new_balance))
            
            connection.commit()
            
            return jsonify({
                'message': 'Withdrawal successful',
                'new_balance': float(new_balance)
            }), 200
            
        finally:
            cursor.close()
            connection.close()
            
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    return jsonify({'message': 'Logout successful'}), 200

if __name__ == '__main__':
    app.run(debug=True)