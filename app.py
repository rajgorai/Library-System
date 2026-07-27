import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
import sqlite3
import hashlib
import random
import string
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client import OAuthError

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this in production
app.config['SESSION_TYPE'] = 'filesystem'

# Flask-Mail config (replace with your Gmail and app password)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_gmail@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
mail = Mail(app)

# OAuth config (replace with your client IDs/secrets from Google Cloud Console and Azure AD)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='129018218607-6eil6n1iihcbg8d57upfo0uakpqgopq4.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
)
microsoft = oauth.register(
    name='microsoft',
    client_id='your_microsoft_client_id',
    client_secret='your_microsoft_client_secret',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    api_base_url='https://graph.microsoft.com/v1.0/',
    client_kwargs={'scope': 'openid email profile'},
)

def get_db():
    conn = sqlite3.connect('online_library.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('dashboard.html')
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('home'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        email = request.form['email']
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.')
        conn.close()
    return render_template('register.html')

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/microsoft')
def login_microsoft():
    redirect_uri = url_for('authorize_microsoft', _external=True)
    return microsoft.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        email = user_info['email']
        name = user_info.get('name', email.split('@')[0])
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            conn.execute('INSERT INTO users (username, email, role) VALUES (?, ?, ?)', (name, email, 'user'))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        session['user_id'] = user['id']
        session['role'] = user['role']
        return redirect(url_for('home'))
    except OAuthError as e:
        flash('OAuth error: ' + str(e))
        return redirect(url_for('login'))

@app.route('/authorize/microsoft')
def authorize_microsoft():
    try:
        token = microsoft.authorize_access_token()
        resp = microsoft.get('me')
        user_info = resp.json()
        email = user_info['mail']
        name = user_info.get('displayName', email.split('@')[0])
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            conn.execute('INSERT INTO users (username, email, role) VALUES (?, ?, ?)', (name, email, 'user'))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        session['user_id'] = user['id']
        session['role'] = user['role']
        return redirect(url_for('home'))
    except OAuthError as e:
        flash('OAuth error: ' + str(e))
        return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form['identifier']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', (identifier, identifier)).fetchone()
        conn.close()
        if user and user['email']:
            otp = ''.join(random.choices(string.digits, k=6))
            expiry = datetime.now() + timedelta(minutes=10)
            session['reset_otp'] = otp
            session['reset_user'] = user['id']
            session['reset_expiry'] = expiry.isoformat()
            msg = Message('Password Reset OTP', sender='your_gmail@gmail.com', recipients=[user['email']])
            msg.body = f'Your OTP is {otp}. It expires in 10 minutes.'
            mail.send(msg)
            flash('OTP sent to your email.')
            return redirect(url_for('reset_password'))
        flash('User not found or no email associated.')
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        if session.get('reset_otp') == otp and datetime.now() < datetime.fromisoformat(session['reset_expiry']):
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            conn = get_db()
            conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['reset_user']))
            conn.commit()
            conn.close()
            session.pop('reset_otp', None)
            session.pop('reset_user', None)
            session.pop('reset_expiry', None)
            flash('Password reset successful. Please login.')
            return redirect(url_for('login'))
        flash('Invalid or expired OTP.')
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/books', methods=['GET', 'POST'])
def books():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    if request.method == 'POST' and session.get('role') == 'admin':
        title = request.form['title']
        author = request.form['author']
        isbn = request.form['isbn']
        conn.execute('INSERT INTO books (title, author, isbn) VALUES (?, ?, ?)', (title, author, isbn))
        conn.commit()
        flash('Book added successfully.')
    books = conn.execute('SELECT * FROM books').fetchall()
    conn.close()
    return render_template('books.html', books=books)

@app.route('/borrow/<int:book_id>')
def borrow(book_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    book = conn.execute('SELECT * FROM books WHERE id = ? AND available = 1', (book_id,)).fetchone()
    if book:
        conn.execute('INSERT INTO borrows (user_id, book_id, borrow_date) VALUES (?, ?, ?)', (session['user_id'], book_id, datetime.now().isoformat()))
        conn.execute('UPDATE books SET available = 0 WHERE id = ?', (book_id,))
        conn.commit()
        flash('Book borrowed successfully.')
    conn.close()
    return redirect(url_for('books'))

@app.route('/return/<int:borrow_id>')
def return_book(borrow_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    borrow = conn.execute('SELECT * FROM borrows WHERE id = ? AND user_id = ?', (borrow_id, session['user_id'])).fetchone()
    if borrow:
        conn.execute('UPDATE borrows SET return_date = ? WHERE id = ?', (datetime.now().isoformat(), borrow_id))
        conn.execute('UPDATE books SET available = 1 WHERE id = ?', (borrow['book_id'],))
        conn.commit()
        flash('Book returned successfully.')
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    borrows = conn.execute('SELECT b.title, br.borrow_date, br.return_date, br.id FROM borrows br JOIN books b ON br.book_id = b.id WHERE br.user_id = ?', (session['user_id'],)).fetchall()
    notifications = conn.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY date DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', borrows=borrows, notifications=notifications)

# Admin Routes
@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/remove_user/<int:user_id>')
def remove_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User removed successfully.')
    return redirect(url_for('admin_users'))

@app.route('/admin/notify_user/<int:user_id>', methods=['GET', 'POST'])
def notify_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message']
        conn = get_db()
        conn.execute('INSERT INTO notifications (user_id, message, date) VALUES (?, ?, ?)', (user_id, message, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        flash('Notification sent.')
        return redirect(url_for('admin_users'))
    return render_template('notify_user.html', user_id=user_id)

@app.route('/admin/remove_book/<int:book_id>')
def remove_book(book_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    conn.execute('DELETE FROM books WHERE id = ?', (book_id,))
    conn.commit()
    conn.close()
    flash('Book removed successfully.')
    return redirect(url_for('books'))

@app.route('/admin/add_admin', methods=['GET', 'POST'])
def add_admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, 'admin'))
            conn.commit()
            flash('Admin added successfully.')
            return redirect(url_for('admin_users'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
        conn.close()
    return render_template('add_admin.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_key')