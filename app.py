# =========================================
#          IMPORTS SECTION
# =========================================

# --- Standard Python Libraries ---
import os
import io
import json
import datetime

# --- Flask Core Libraries ---
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, abort, make_response)

# --- Flask Extensions ---
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, login_user, current_user,
                         logout_user, login_required, UserMixin)
from flask_wtf import FlaskForm

# --- WTForms Libraries ---
# Import Fields from wtforms.fields (DateField is now here in WTForms 3+)
from wtforms.fields import (StringField, PasswordField, BooleanField,
                            SubmitField, TextAreaField, FieldList, DateField)
# Import Validators from wtforms.validators
from wtforms.validators import (DataRequired, Length, EqualTo, ValidationError)

# --- Other Third-Party Libraries ---
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# =========================================
#          END IMPORTS SECTION
# =========================================


# --- Flask App Initialization and Configuration ---
# Example: app = Flask(__name__)
#          app.config[...] = ...
#          db = SQLAlchemy(app)
#          bcrypt = Bcrypt(app)
#          login_manager = LoginManager(app)
#          ... etc ...
# Create a Flask application instance
app = Flask(__name__)


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
login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(user_id):
    # user_id is a string, convert it to integer for querying
    return User.query.get(int(user_id))
login_manager.login_view = 'login' # Route function name for the login page
login_manager.login_message_category = 'info' # Bootstrap category for flash message
# --- End Initialize Extensions ---


# Add UserMixin here         vvvvvvvvvv
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)

    # No need to define is_authenticated, is_active, etc. manually
    # Relationship: One-to-Many (One User can have Many Meetings)
    meetings = db.relationship('Meeting', backref='author', lazy=True)
    def __repr__(self):
        return f"User('{self.username}')"
    pass

# --- Define Forms ---
class RegistrationForm(FlaskForm):
    # Username Field: Required, Length between 2 and 20 characters
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    # Password Field: Required
    password = PasswordField('Password', validators=[DataRequired()])
    # Confirm Password Field: Required, Must be equal to 'password' field
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    # Submit Button
    submit = SubmitField('Sign Up')

    # Custom validator: Check if username already exists
    def validate_username(self, username):
        # Query the database to see if a user with this username exists
        user = User.query.filter_by(username=username.data).first()
        if user:
            # If user exists, raise a validation error
            raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    # Use username for login in this example
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    # Remember Me checkbox
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# Meeting Form: This is a placeholder for the meeting form
class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False) # Meeting title, required
    # Using DateTime for meeting date/time
    meeting_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    # Using Text for potentially longer content
    attendees = db.Column(db.Text, nullable=True) # Optional for now
    agenda = db.Column(db.Text, nullable=False) # Required
    minutes = db.Column(db.Text, nullable=True) # Optional
    action_items = db.Column(db.Text, nullable=True) # Optional
    # Timestamp for when the record was created
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    # Foreign Key to link to the user who created the meeting
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Meeting('{self.title}', '{self.meeting_date}')"

# ... (Forms definition) ...
# --- End Define Forms ---


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html', title='Home') # Added title

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Create an instance of the registration form
    form = RegistrationForm()

    # Check if the form was submitted and passed validation rules
    if form.validate_on_submit(): # This handles POST requests and validation
        # Hash the password before saving
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Create a new User instance with data from the form
        user = User(username=form.username.data, password_hash=hashed_password)
        # Add the new user to the database session
        db.session.add(user)
        # Commit the changes to the database
        db.session.commit()
        # Flash a success message to the user
        flash(f'Account created for {form.username.data}! You can now log in.', 'success') # 'success' is a category
        # Redirect the user to the login page (we'll create this soon)
        return redirect(url_for('login')) # Redirect to login route

    # If it's a GET request or form validation failed, render the registration template
    return render_template('register.html', title='Register', form=form)

# We need a login route for the redirect, let's add a placeholder for now
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect them to homepage
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        # Query the database for the user by the entered username
        user = User.query.filter_by(username=form.username.data).first()
        # Check if user exists and the entered password matches the stored hash
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            # Log the user in using Flask-Login
            login_user(user, remember=form.remember.data)
            # Check if the user was redirected from a protected page
            next_page = request.args.get('next')
            flash('Login Successful!', 'success')
            # Redirect to the originally requested page (if any) or homepage
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            # If login fails (user not found or password incorrect)
            flash('Login Unsuccessful. Please check username and password', 'danger') # 'danger' category

    # If GET request or login failed, render the login page again
    return render_template('login.html', title='Login', form=form)



class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    meeting_date = DateField('Meeting Date', format='%Y-%m-%d', validators=[DataRequired()])
    attendees = TextAreaField('Attendees')
    agenda_items = FieldList(StringField('Agenda Item', validators=[DataRequired()]), min_entries=0, label='Agenda Items')
    minutes = TextAreaField('Minutes')
    action_items = TextAreaField('Action Items')
    submit = SubmitField('Save Meeting')

# ... (Routes definition) ...

@app.route('/logout')
def logout():
    logout_user() # Logs the user out (clears the session)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))




# Make sure these imports are included at the top of app.py
# import json
# from flask import request, redirect, url_for, flash, render_template
# from .models import Meeting, db # Adjust import based on your structure
# from .forms import MeetingForm # Adjust import based on your structure
# from flask_login import current_user, login_required

@app.route("/meeting/new", methods=['GET', 'POST'])
@login_required
def new_meeting():
    form = MeetingForm()
    # This block executes only on POST requests with valid data
    if form.validate_on_submit():
        agenda_list_from_request = request.form.getlist('agenda_items')
        agenda_list_filtered = [item for item in agenda_list_from_request if item.strip()]
        print(f"DEBUG: Filtered agenda list from request: {agenda_list_filtered}")
        print(f"DEBUG: Raw data from Flask request.form: {request.form.getlist('agenda_items')}")
        print(f"DEBUG: Raw entries in form.agenda_items: {form.agenda_items.entries}")
        print(f"DEBUG: Processed form.agenda_items.data: {form.agenda_items.data}")
        agenda_json_string = json.dumps(agenda_list_filtered)
        print(f"DEBUG: JSON string being saved: {agenda_json_string}")

        # --- Create and Save Meeting Object ---
        meeting = Meeting(title=form.title.data,
                          meeting_date=form.meeting_date.data,
                          attendees=form.attendees.data,
                          agenda=agenda_json_string, # Use the JSON string
                          minutes=form.minutes.data,
                          action_items=form.action_items.data,
                          author=current_user)
        db.session.add(meeting)
        db.session.commit()
        flash('Your meeting has been created!', 'success')
        return redirect(url_for('meetings_list'))

    # --- Render Template for GET requests or Invalid POST ---
    # This line runs if it's a GET request OR if form.validate_on_submit() was False
    return render_template('create_meeting.html', title='New Meeting', form=form, legend='New Meeting')

@app.route("/meetings")
@login_required 
def meetings_list():
    meetings = Meeting.query.filter_by(author=current_user)\
                            .order_by(Meeting.date_posted.desc()).all()
    # Render the template, passing the list of meetings to it
    return render_template('meetings.html', title='My Meetings', meetings=meetings)





@app.route("/meeting/<int:meeting_id>")
@login_required
def meeting_detail(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)  
    try:
        agenda_list = json.loads(meeting.agenda)
        if not isinstance(agenda_list, list):
            agenda_list = [] # Default to empty list if not a list
    except (json.JSONDecodeError, TypeError):
        agenda_list = [] # Default to an empty list
    return render_template('meeting_detail.html', title=meeting.title, meeting=meeting, agenda_list=agenda_list) # Pass agenda_list





# Ensure these imports are at the top:
# import io, json
# from fpdf import FPDF
# from fpdf.enums import XPos, YPos
# from flask import make_response, abort, current_app
# from flask_login import login_required, current_user
# from .models import Meeting # Adjust import based on your structure

@app.route("/meeting/<int:meeting_id>/pdf")
@login_required
def generate_meeting_pdf(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)

    if meeting.author != current_user:
        abort(403)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)

    # --- Nested Helper Function ---
    def add_section(title, content):
        effective_width = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Arial', '', 12)
        if isinstance(content, list):
            if content:
                for item in content:
                    pdf.set_x(pdf.l_margin)
                    pdf.multi_cell(effective_width, 5, f"- {item}")
                pdf.ln(2) # Add a bit of space after list items
            else:
                 pdf.multi_cell(effective_width, 5, "N/A")
        else: # Handle simple strings (or None)
            pdf.multi_cell(effective_width, 5, content if content else "N/A")
        pdf.ln(5) # Space after section
    # --- End Nested Helper Function ---

    # --- Add PDF Content ---
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'Meeting Minutes: {meeting.title}', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(10)

    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 7, f'Date: {meeting.meeting_date.strftime("%Y-%m-%d")}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f'Recorded By: {meeting.author.username}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # --- Parse Agenda JSON ---
    try:
        agenda_items_list = json.loads(meeting.agenda)
        if not isinstance(agenda_items_list, list): agenda_items_list = []
    except (json.JSONDecodeError, TypeError):
        agenda_items_list = []
    # --- End Parse ---

    # --- Call Helper for Sections ---
    add_section('Attendees', meeting.attendees)
    add_section('Agenda', agenda_items_list) # Pass the parsed list
    add_section('Minutes', meeting.minutes)
    add_section('Action Items', meeting.action_items)
    # --- End Call ---

    # --- Generate PDF Bytes ---
    pdf_buffer = io.BytesIO()
    pdf.output(pdf_buffer)
    pdf_bytes = pdf_buffer.getvalue()

    # --- Create and Return Response ---
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=meeting_{meeting.id}_{meeting.title.replace(" ", "_")}.pdf'

    return response









# --- End Routes ---


# Run the development server
if __name__ == '__main__':
    # Need to create the context for db operations in shell
    with app.app_context():
         db.create_all() # Ensure tables are created if they don't exist
    app.run(debug=True)




# Run the development server
if __name__ == '__main__':
    app.run(debug=True)