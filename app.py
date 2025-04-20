# =========================================
#          IMPORTS SECTION
# =========================================
# --- Standard Python Libraries ---
import os
from dotenv import load_dotenv
import io
import json
import datetime

# Inside app.py, after imports
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
print(f"DEBUG: Looking for .env file at: {dotenv_path}")
# Add override=True here:
load_ok = load_dotenv(dotenv_path=dotenv_path, verbose=True, override=True)
print(f"DEBUG: load_dotenv() returned: {load_ok}")
print(f"DEBUG: Value of DATABASE_URL from os.environ AFTER load: {os.environ.get('DATABASE_URL')}")

# --- Flask Core Libraries ---
from flask import (Flask, render_template, redirect, url_for,
                   flash, request, abort, make_response)

# --- Flask Extensions ---
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, login_user, current_user,
                         logout_user, login_required, UserMixin)
from flask_wtf import FlaskForm
from flask_migrate import Migrate

# --- WTForms ---
from wtforms import (Form, StringField, PasswordField, BooleanField,  # Added Form
                     SubmitField, TextAreaField, FieldList, FormField) # Added FormField
from wtforms.fields import DateField # DateField is here
from wtforms.validators import (DataRequired, Length, EqualTo,        # For MeetingForm & ActionItemForm validators
                            ValidationError, Optional)            # Added Optional for ActionItemForm

# --- End WTForms Imports ---

# --- Other Third-Party Libraries ---
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# =========================================
#          END IMPORTS SECTION
# =========================================


# Ensure 'os', 'Flask', 'SQLAlchemy', 'Bcrypt', 'LoginManager', 'User' are imported
# Ensure 'load_dotenv()' has been called earlier if using .env file

app = Flask(__name__)

# --- Load configurations from environment variables ---
# This print is helpful too, to see value just before the check
print(f"DEBUG: Value of DATABASE_URL from os.environ BEFORE check: {os.environ.get('DATABASE_URL')}")
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY environment variable not set.")

database_uri = os.environ.get('DATABASE_URL')
if not database_uri or not database_uri.startswith('postgresql://'):
    raise ValueError("DATABASE_URL environment variable is not set or invalid for PostgreSQL.")
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    try:
        # Using User.query.get() for now
        return User.query.get(int(user_id))
    except ValueError:
        return None
    except Exception as e:
        # Basic error logging can be helpful
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# Flask-Migrate initialization will go here in the next step




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






class ActionItemForm(Form): # Inherit from wtforms.Form
    # Using TextAreaField for potentially longer descriptions
    description = TextAreaField('Description') # Maybe add validators=[DataRequired()] if needed? Let's make it optional for now.
    # Simple StringField for assignee name (text input)
    assigned_to = StringField('Assigned To') # Optional for now
    # DateField for deadline, also optional
    deadline = DateField('Deadline', format='%Y-%m-%d', validators=[Optional()])



class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    meeting_date = DateField('Meeting Date', format='%Y-%m-%d', validators=[DataRequired()])
    attendees = FieldList(StringField('Attendee'), min_entries=0, label='Attendees')
    agenda_items = FieldList(StringField('Agenda Item', validators=[DataRequired()]), min_entries=0, label='Agenda Items')
    minutes = TextAreaField('Minutes')

    # --- Changed Action Items Field ---
    action_items = FieldList(
        FormField(ActionItemForm), # Embed ActionItemForm using FormField
        min_entries=0,
        label='Action Items'
    )
    # --- End Change ---

    submit = SubmitField('Save Meeting')





# ... (Routes definition) ...

@app.route('/logout')
def logout():
    logout_user() # Logs the user out (clears the session)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))



# Ensure imports: json, datetime, Meeting, db, MeetingForm, flash, redirect, url_for, login_required, current_user
@app.route("/meeting/new", methods=['GET', 'POST'])
@login_required
def new_meeting():
    form = MeetingForm()
    if form.validate_on_submit():
        agenda_list_from_form = form.agenda_items.data
        agenda_list_filtered = [item for item in agenda_list_from_form if isinstance(item, str) and item.strip()]
        agenda_json_string = json.dumps(agenda_list_filtered)

        attendees_list_from_form = form.attendees.data
        attendees_list_filtered = [item for item in attendees_list_from_form if isinstance(item, str) and item.strip()]
        attendees_json_string = json.dumps(attendees_list_filtered)

        action_items_data = form.action_items.data
        serializable_action_items = []
        for item in action_items_data:
            if isinstance(item.get('deadline'), datetime.date):
                item['deadline'] = item['deadline'].isoformat()
            serializable_action_items.append(item)
        action_items_json_string = json.dumps(serializable_action_items)

        meeting = Meeting(title=form.title.data,
                          meeting_date=form.meeting_date.data,
                          attendees=attendees_json_string,
                          agenda=agenda_json_string,
                          minutes=form.minutes.data,
                          action_items=action_items_json_string,
                          author=current_user)
        db.session.add(meeting)
        db.session.commit()
        flash('Your meeting has been created!', 'success')
        return redirect(url_for('meetings_list'))

    return render_template('create_meeting.html', title='New Meeting', form=form, legend='New Meeting')






@app.route("/meetings")
@login_required 
def meetings_list():
    meetings = Meeting.query.filter_by(author=current_user)\
                            .order_by(Meeting.date_posted.desc()).all()
    # Render the template, passing the list of meetings to it
    return render_template('meetings.html', title='My Meetings', meetings=meetings)





# Ensure necessary imports: json, Meeting, abort, render_template, login_required, current_user
@app.route("/meeting/<int:meeting_id>")
@login_required
def meeting_detail(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)

    # Parse Agenda JSON (Existing)
    try:
        agenda_list = json.loads(meeting.agenda or '[]')
        if not isinstance(agenda_list, list): agenda_list = []
    except (json.JSONDecodeError, TypeError):
        agenda_list = []

    # Parse Attendees JSON (Existing)
    try:
        attendees_list = json.loads(meeting.attendees or '[]')
        if not isinstance(attendees_list, list): attendees_list = []
    except (json.JSONDecodeError, TypeError):
        attendees_list = []

    # Parse Action Items JSON (NEW BLOCK)
    # Expecting a list of dictionaries: [{'description':'...', 'assigned_to':'...', 'deadline':'...'}, ...]
    try:
        action_items_list = json.loads(meeting.action_items or '[]')
        if not isinstance(action_items_list, list): action_items_list = []
        # Note: deadline is stored as 'YYYY-MM-DD' string from DateField
    except (json.JSONDecodeError, TypeError):
        action_items_list = []
    # End Parse Action Items

    # Pass ALL lists to the template (UPDATED)
    return render_template('meeting_detail.html', title=meeting.title, meeting=meeting,
                           agenda_list=agenda_list,
                           attendees_list=attendees_list,
                           action_items_list=action_items_list) # Pass action_items_list





# Ensure FPDF is imported: from fpdf import FPDF
# Ensure datetime is imported: import datetime

class MyPDF(FPDF):
    def __init__(self, orientation='P', unit='mm', format='A4', meeting_title="Meeting Minutes"):
        super().__init__(orientation, unit, format)
        self.meeting_title = meeting_title
        # Store the actual datetime object for potential internal FPDF use
        self.creation_datetime_obj = datetime.datetime.now()
        # Store a formatted string specifically for display in the header
        self.creation_date_str = self.creation_datetime_obj.strftime("%Y-%m-%d %H:%M")
        # self.set_auto_page_break(auto=True, margin=15) # Optional: Keep if needed

    def header(self):
        self.set_font('Arial', 'B', 12)
        title_w = self.get_string_width(self.meeting_title) + 6
        doc_w = self.w
        self.set_x((doc_w - title_w) / 2)
        self.cell(title_w, 10, self.meeting_title, border=0, ln=False, align='C')
        self.set_font('Arial', '', 8)
        # Use the formatted string for display
        self.cell(0, 10, f"Created: {self.creation_date_str}", border=0, ln=True, align='R')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

# --- End of MyPDF class ---




# Ensure necessary imports: json, io, datetime, FPDF, MyPDF, XPos, YPos, Meeting, db, abort, make_response, login_required, current_user
@app.route("/meeting/<int:meeting_id>/pdf")
@login_required
def generate_meeting_pdf(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)

    pdf_title = f'Meeting: {meeting.title}'
    pdf = MyPDF(meeting_title=pdf_title)
    pdf.alias_nb_pages()
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
                    pdf.set_x(pdf.l_margin) # Reset X for each item
                    if isinstance(item, dict): # Action Item
                        desc = item.get('description', '')
                        assignee = item.get('assigned_to', '')
                        deadline_str = item.get('deadline', '')
                        assignee_deadline_text = ""
                        if assignee:
                            assignee_deadline_text += f"Assigned: {assignee}"
                        if deadline_str:
                            if assignee: assignee_deadline_text += "  |  " # Separator
                            assignee_deadline_text += f"Deadline: {deadline_str}"

                        if assignee_deadline_text: # Print line 1 only if needed
                            pdf.set_font('Arial', 'I', 10) # Italic, smaller
                            pdf.multi_cell(effective_width, 4, assignee_deadline_text) # Smaller height
                            pdf.set_x(pdf.l_margin) # Reset X

                        pdf.set_font('Arial', '', 12) # Back to normal for description
                        pdf.set_x(pdf.l_margin + 5)   # Indent description
                        desc_width = effective_width - 5
                        pdf.multi_cell(desc_width, 5, f"- {desc}" if desc else "- N/A")
                        pdf.ln(3) # Space after this action item
                    else: # Agenda / Attendee
                        pdf.multi_cell(effective_width, 5, f"- {str(item)}")
                # pdf.ln(2) # Removed this as space is added after each action item now
            else:
                 pdf.multi_cell(effective_width, 5, "N/A") # Empty list
        else: # Minutes (Simple string)
            pdf.multi_cell(effective_width, 5, content if content else "N/A")
        pdf.ln(5) # Space after section
    # --- End Nested Helper Function ---

    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 7, f'Date: {meeting.meeting_date.strftime("%Y-%m-%d")}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f'Recorded By: {meeting.author.username}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    try: agenda_list = json.loads(meeting.agenda or '[]')
    except: agenda_list = []
    try: attendees_list = json.loads(meeting.attendees or '[]')
    except: attendees_list = []
    try:
        action_items_list = json.loads(meeting.action_items or '[]')
        if not isinstance(action_items_list, list): action_items_list = []
    except: action_items_list = []

    add_section('Attendees', attendees_list)
    add_section('Agenda', agenda_list)
    add_section('Minutes', meeting.minutes)
    add_section('Action Items', action_items_list)

    pdf_buffer = io.BytesIO()
    pdf.output(pdf_buffer)
    pdf_bytes = pdf_buffer.getvalue()

    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=meeting_{meeting.id}_{meeting.title.replace(" ", "_")}.pdf'
    return response








# Ensure necessary imports: json, datetime, Meeting, db, MeetingForm, flash, redirect, url_for, login_required, current_user, request, abort, render_template
@app.route("/meeting/<int:meeting_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)

    form = MeetingForm()

    if form.validate_on_submit(): # Handle POST request
        agenda_list_from_form = form.agenda_items.data
        agenda_list_filtered = [item for item in agenda_list_from_form if isinstance(item, str) and item.strip()]
        agenda_json_string = json.dumps(agenda_list_filtered)

        attendees_list_from_form = form.attendees.data
        attendees_list_filtered = [item for item in attendees_list_from_form if isinstance(item, str) and item.strip()]
        attendees_json_string = json.dumps(attendees_list_filtered)

        action_items_data = form.action_items.data
        serializable_action_items = []
        for item in action_items_data:
            if isinstance(item.get('deadline'), datetime.date):
                item['deadline'] = item['deadline'].isoformat()
            serializable_action_items.append(item)
        action_items_json_string = json.dumps(serializable_action_items)

        meeting.title = form.title.data
        meeting.meeting_date = form.meeting_date.data
        meeting.attendees = attendees_json_string
        meeting.agenda = agenda_json_string
        meeting.minutes = form.minutes.data
        meeting.action_items = action_items_json_string

        db.session.commit()
        flash('Your meeting has been updated!', 'success')
        return redirect(url_for('meeting_detail', meeting_id=meeting.id))

    elif request.method == 'GET': # Handle GET request
        try:
            agenda_list = json.loads(meeting.agenda or '[]')
            if not isinstance(agenda_list, list): agenda_list = []
        except: agenda_list = []

        try:
            attendees_list = json.loads(meeting.attendees or '[]')
            if not isinstance(attendees_list, list): attendees_list = []
        except: attendees_list = []

        try:
            action_items_list = json.loads(meeting.action_items or '[]')
            if not isinstance(action_items_list, list): action_items_list = []
        except: action_items_list = []

        # Pre-populate only simple fields on the blank form object
        form.title.data = meeting.title
        form.meeting_date.data = meeting.meeting_date
        form.minutes.data = meeting.minutes

        # --- FINAL CHECK PRINT ---
        # Print the list just before sending it to the template
        print(f"FINAL CHECK [EDIT GET] - Passing action_items_list: {action_items_list}")
        # --- END FINAL CHECK ---

        # Render template, passing the BLANK form AND the data lists
        return render_template('create_meeting.html', title='Edit Meeting', form=form, legend='Edit Meeting',
                               attendees_list=attendees_list,
                               agenda_list=agenda_list,
                               action_items_list=action_items_list) # Pass the list here

    # This part might be unreachable if GET always renders, but good practice
    return render_template('create_meeting.html', title='Edit Meeting', form=form, legend='Edit Meeting')









# Ensure imports: redirect, url_for, flash, abort, db, Meeting, login_required, current_user

@app.route("/meeting/<int:meeting_id>/delete", methods=['POST']) # Only accept POST requests
@login_required
def delete_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    # Authorization: Only the author can delete
    if meeting.author != current_user:
        abort(403)

    # Delete the meeting object from the database session
    db.session.delete(meeting)
    # Commit the change to permanently remove it
    db.session.commit()

    flash('Your meeting has been deleted!', 'success')
    # Redirect to the meetings list page after deletion
    return redirect(url_for('meetings_list'))



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