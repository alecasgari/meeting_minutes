import os # Import the os module
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy # Import SQLAlchemy
from flask_bcrypt import Bcrypt        # Import Bcrypt
# Flask-WTF needs a secret key, we'll add WTForms later
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, Length, EqualTo, ValidationError


# Create a Flask application instance
app = Flask(__name__)

# --- New Configurations ---
# Secret Key: Needed for session management and Flask-WTF (CSRF protection)
# Should be a long, random string in production. Keep it secret!
# For development, we can use a simple one or generate one.
app.config['SECRET_KEY'] = 'a_very_secret_key_for_development_12345' # CHANGE THIS LATER!

# Database Configuration: Use SQLite for local development
# Get the base directory of the project
basedir = os.path.abspath(os.path.dirname(__file__))
# Set the database URI (path to the SQLite file)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
# Optional: Disable track modifications to save resources if you don't need it
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- End New Configurations ---

# --- Initialize Extensions ---
db = SQLAlchemy(app)   # Initialize SQLAlchemy with our app
bcrypt = Bcrypt(app)   # Initialize Bcrypt with our app
# --- End Initialize Extensions ---


# --- Define Database Models ---
# We will define the User model here soon
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) # Primary key
    username = db.Column(db.String(20), unique=True, nullable=False) # Username, max 20 chars, unique, required
    # We store password hashes, not passwords! Increased length for hash.
    password_hash = db.Column(db.String(60), nullable=False) # Hashed password, required

    # Optional: How the object is represented when printed
    def __repr__(self):
        return f"User('{self.username}')"
# --- End Define Database Models ---


# Route for the homepage ('/')
@app.route('/')
def index():
    return render_template('index.html')

# Run the development server
if __name__ == '__main__':
    app.run(debug=True)