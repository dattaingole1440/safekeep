# Import necessary tools from Flask and other libraries
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# --- INITIAL SETUP ---

# Create the main application object
app = Flask(__name__)

# Configure the application
# SECRET_KEY is crucial for security, it keeps user sessions safe
app.config['SECRET_KEY'] = os.urandom(24) 
# This is where our database will be stored
# Get the database URL from the hosting environment (like Render)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("://", "ql://", 1) 
# This setting is to quiet a deprecation warning
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

# Initialize the database connection
db = SQLAlchemy(app)


# --- DATABASE MODELS (The blueprint for our data) ---

# User model: Defines the table for user accounts
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # This creates a relationship, so we can easily get all notes/contacts for a user
    notes = db.relationship('Note', backref='author', lazy=True, cascade="all, delete-orphan")
    contacts = db.relationship('Contact', backref='owner', lazy=True, cascade="all, delete-orphan")

# Note model: Defines the table for notes
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Contact model: Defines the table for mobile numbers/contacts
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    number = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- WEBSITE ROUTES (The different pages and actions) ---

# Homepage Route: Handles login
@app.route('/', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, send them to their dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    # If the form is submitted
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # If details are wrong, show an error message
            flash('Invalid username or password. Please try again or sign up.', 'danger')

    return render_template('login.html')

# Signup Route: Handles new account creation
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('That username is already taken. Please choose another.', 'warning')
            return redirect(url_for('signup'))

        # Hash the password for security before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Create a new user and save to database
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Dashboard Route: The main page after logging in
@app.route('/dashboard')
def dashboard():
    # Protect the page: if not logged in, redirect to login
    if 'user_id' not in session:
        flash('You need to be logged in to see that page.', 'warning')
        return redirect(url_for('login'))
    
    # Get the current user's data from the database
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', notes=user.notes, contacts=user.contacts)

# Add Note Action
@app.route('/add_note', methods=['POST'])
def add_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form['content']
    if content:
        new_note = Note(content=content, user_id=session['user_id'])
        db.session.add(new_note)
        db.session.commit()
        flash('Note added!', 'success')
    return redirect(url_for('dashboard'))

# Delete Note Action
@app.route('/delete_note/<int:note_id>')
def delete_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    note_to_delete = Note.query.get_or_404(note_id)
    # Security check: Make sure the note belongs to the logged-in user
    if note_to_delete.user_id != session['user_id']:
        flash('You do not have permission to delete this note.', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(note_to_delete)
    db.session.commit()
    flash('Note deleted.', 'success')
    return redirect(url_for('dashboard'))

# Add Contact Action
@app.route('/add_contact', methods=['POST'])
def add_contact():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    name = request.form['name']
    number = request.form['number']
    if name and number:
        new_contact = Contact(name=name, number=number, user_id=session['user_id'])
        db.session.add(new_contact)
        db.session.commit()
        flash('Contact added!', 'success')
    return redirect(url_for('dashboard'))

# Delete Contact Action
@app.route('/delete_contact/<int:contact_id>')
def delete_contact(contact_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    contact_to_delete = Contact.query.get_or_404(contact_id)
    # Security check: Make sure the contact belongs to the logged-in user
    if contact_to_delete.user_id != session['user_id']:
        flash('You do not have permission to delete this contact.', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(contact_to_delete)
    db.session.commit()
    flash('Contact deleted.', 'success')
    return redirect(url_for('dashboard'))

# Logout Action
@app.route('/logout')
def logout():
    session.clear() # Clears all data from the session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# --- MAIN EXECUTION ---
# This part runs the app
if __name__ == '__main__':
    # Before the first request, create the database tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True helps with development, turn off for production