import os # Import the os module
import datetime # Import datetime for date/time operations
from flask import Flask, render_template, redirect, url_for, flash # Add redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy # Import SQLAlchemy
from flask_bcrypt import Bcrypt        # Import Bcrypt
# --- WTForms Imports ---
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
# --- End WTForms Imports ---
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin # Add these
from flask import request # Needed for 'next' parameter in login
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from wtforms.fields import DateField # Correct import for WTForms 3+
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField # Add TextAreaField
from flask import abort # Import abort at the top
from fpdf import FPDF
from flask import make_response
import io
from fpdf.enums import XPos, YPos
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



# ... (RegistrationForm, LoginForm) ...

class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    # Using DateField for browser's native date picker
    meeting_date = DateField('Meeting Date', format='%Y-%m-%d', validators=[DataRequired()])
    # Using TextAreaField for potentially multi-line text
    attendees = TextAreaField('Attendees')
    agenda = TextAreaField('Agenda', validators=[DataRequired()])
    minutes = TextAreaField('Minutes')
    action_items = TextAreaField('Action Items')
    submit = SubmitField('Save Meeting')

# ... (Routes definition) ...

@app.route('/logout')
def logout():
    logout_user() # Logs the user out (clears the session)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))



# --- Routes ---
# ... (index, register, login, logout routes) ...

@app.route("/meeting/new", methods=['GET', 'POST'])
@login_required # Only logged-in users can create meetings
def new_meeting():
    form = MeetingForm()
    if form.validate_on_submit():
        # Create a new Meeting object using form data
        # Note: We set the 'author' using the backref, SQLAlchemy handles user_id
        meeting = Meeting(title=form.title.data,
                          meeting_date=form.meeting_date.data,
                          attendees=form.attendees.data,
                          agenda=form.agenda.data,
                          minutes=form.minutes.data,
                          action_items=form.action_items.data,
                          author=current_user) # Associate with the logged-in user
        db.session.add(meeting)
        db.session.commit()
        flash('Your meeting has been created!', 'success')
        # Redirect to homepage for now, later maybe to a meetings list page
        return redirect(url_for('index'))
    # If GET request, render the form
    return render_template('create_meeting.html', title='New Meeting', form=form, legend='New Meeting')



@app.route("/meetings")
@login_required # <--- این دکوراتور رو دوباره فعال کن!
def meetings_list():
    # Query the database for all meetings authored by the current user
    # Order them by date posted in descending order (newest first)
    meetings = Meeting.query.filter_by(author=current_user)\
                            .order_by(Meeting.date_posted.desc()).all()
    # Render the template, passing the list of meetings to it
    return render_template('meetings.html', title='My Meetings', meetings=meetings)





@app.route("/meeting/<int:meeting_id>") # Route accepts an integer in the URL
@login_required
def meeting_detail(meeting_id):
    # Query the database for the meeting with the given ID
    # get_or_404: Get the meeting or return a 404 Not Found error if ID doesn't exist
    meeting = Meeting.query.get_or_404(meeting_id)

    # --- Authorization Check (Optional but Recommended) ---
    # Make sure the logged-in user is the author of the meeting
    if meeting.author != current_user:
        abort(403) # Forbidden access - Return a 403 error page
    # --- End Authorization Check ---

    # Render a template, passing the specific meeting object to it
    return render_template('meeting_detail.html', title=meeting.title, meeting=meeting)



@app.route("/meeting/<int:meeting_id>/pdf")
@login_required
def generate_meeting_pdf(meeting_id):
    # 1. Get Meeting Data (or 404)
    meeting = Meeting.query.get_or_404(meeting_id)

    # 2. Authorization Check
    if meeting.author != current_user:
        abort(403)

    # 3. Create PDF object
    pdf = FPDF()
    pdf.add_page()

    # 4. Set Font (Using Arial, will fallback to Helvetica)
    # Note: Font warnings might still appear if Arial isn't truly available/embedded
    pdf.set_font('Arial', '', 12)

    # 5. Add Content to PDF
    # --- Title ---
    pdf.set_font('Arial', 'B', 16)
    # Use new_x and new_y instead of ln=True
    pdf.cell(0, 10, f'Meeting Minutes: {meeting.title}', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(10) # Keep pdf.ln() for adding vertical space explicitly

    # --- Basic Info ---
    pdf.set_font('Arial', '', 12)
    # Use new_x and new_y instead of ln=True
    pdf.cell(0, 7, f'Date: {meeting.meeting_date.strftime("%Y-%m-%d")}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f'Recorded By: {meeting.author.username}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # --- Sections (using multi_cell for wrapping text) ---
    # Helper function to add sections consistently
    def add_section(title, content):
        pdf.set_font('Arial', 'B', 14)
        # Use new_x and new_y instead of ln=True for the section title cell
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Arial', '', 12)
        # multi_cell handles line breaks internally, no ln=True needed here
        pdf.multi_cell(0, 5, content if content else "N/A")
        pdf.ln(5) # Add space after the multi_cell content

    # Add the actual sections using the helper function
    add_section('Attendees', meeting.attendees)
    add_section('Agenda', meeting.agenda)
    add_section('Minutes', meeting.minutes)
    add_section('Action Items', meeting.action_items)

    # 6. Generate PDF output into a BytesIO buffer
    pdf_buffer = io.BytesIO()
    pdf.output(pdf_buffer) # Write PDF data to the buffer
    pdf_bytes = pdf_buffer.getvalue() # Get the raw bytes from the buffer

    # 7. Create Flask Response for Download
    response = make_response(pdf_bytes) # pdf_bytes is definitely bytes
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