import os
import io
import json
import datetime
from dotenv import load_dotenv

from flask import (Flask, render_template, redirect, url_for,
                   flash, request, abort, make_response)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, login_user, current_user,
                         logout_user, login_required, UserMixin)
from flask_wtf import FlaskForm
from flask_migrate import Migrate
from wtforms import (Form, StringField, PasswordField, BooleanField,
                     SubmitField, TextAreaField, FieldList, FormField)
from wtforms.fields import DateField
from wtforms.validators import (DataRequired, Length, EqualTo,
                                ValidationError, Optional)
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# --- Load Environment Variables ---
load_dotenv(override=True)

# --- Flask App Initialization & Config ---
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY environment variable not set.")

database_uri = os.environ.get('DATABASE_URL')
if not database_uri or not (database_uri.startswith('postgresql://') or database_uri.startswith('postgresql+psycopg2://')):
    # In production, use app.logger.error or proper logging
    print(f"FATAL ERROR: DATABASE_URL environment variable invalid or not set. Value: {database_uri}")
    raise ValueError("DATABASE_URL environment variable is not set or invalid for PostgreSQL.")
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Initialize Extensions ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- User Loader Callback ---
@login_manager.user_loader
def load_user(user_id):
    try:
        # Using User.query.get() is legacy but works for now
        return User.query.get(int(user_id))
    except ValueError:
        return None
    except Exception as e:
        # Consider adding proper logging in production
        # app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    meetings = db.relationship('Meeting', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}')"

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    meeting_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    attendees = db.Column(db.Text, nullable=True) # JSON string
    agenda = db.Column(db.Text, nullable=True) # JSON string
    minutes = db.Column(db.Text, nullable=True)
    action_items = db.Column(db.Text, nullable=True) # JSON string
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Meeting('{self.title}', '{self.meeting_date.strftime('%Y-%m-%d')}')"

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ActionItemForm(Form):
    description = TextAreaField('Description', validators=[Optional()])
    assigned_to = StringField('Assigned To', validators=[Optional()])
    deadline = DateField('Deadline', format='%Y-%m-%d', validators=[Optional()])

class MeetingForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    meeting_date = DateField('Meeting Date', format='%Y-%m-%d', validators=[DataRequired()])
    attendees = FieldList(StringField('Attendee', validators=[Optional()]), min_entries=0, label='Attendees')
    agenda_items = FieldList(StringField('Agenda Item', validators=[Optional()]), min_entries=0, label='Agenda Items')
    minutes = TextAreaField('Minutes', validators=[Optional()])
    action_items = FieldList(FormField(ActionItemForm), min_entries=0, label='Action Items')
    submit = SubmitField('Save Meeting')

# --- PDF Generation Class ---
class MyPDF(FPDF):
    def __init__(self, orientation='P', unit='mm', format='A4', meeting_title="Meeting Minutes"):
        super().__init__(orientation, unit, format)
        self.meeting_title = meeting_title
        self.creation_datetime_obj = datetime.datetime.now()
        self.creation_date_str = self.creation_datetime_obj.strftime("%Y-%m-%d %H:%M")

    def header(self):
        self.set_font('Arial', 'B', 12)
        title_w = self.get_string_width(self.meeting_title) + 6
        doc_w = self.w
        self.set_x((doc_w - title_w) / 2)
        self.cell(title_w, 10, self.meeting_title, border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')
        self.set_font('Arial', '', 8)
        self.cell(0, 10, f"Created: {self.creation_date_str}", border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='R')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login Successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

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

    # Pass blank form and empty lists for template compatibility with manual rendering
    return render_template('create_meeting.html', title='New Meeting', form=form, legend='New Meeting',
                           attendees_list=[], agenda_list=[], action_items_list=[])

@app.route("/meetings")
@login_required
def meetings_list():
    meetings = Meeting.query.filter_by(author=current_user).order_by(Meeting.date_posted.desc()).all()
    return render_template('meetings.html', title='My Meetings', meetings=meetings)

@app.route("/meeting/<int:meeting_id>")
@login_required
def meeting_detail(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)
    try: agenda_list = json.loads(meeting.agenda or '[]')
    except: agenda_list = []
    try: attendees_list = json.loads(meeting.attendees or '[]')
    except: attendees_list = []
    try: action_items_list = json.loads(meeting.action_items or '[]')
    except: action_items_list = []

    if not isinstance(agenda_list, list): agenda_list = []
    if not isinstance(attendees_list, list): attendees_list = []
    if not isinstance(action_items_list, list): action_items_list = []

    return render_template('meeting_detail.html', title=meeting.title, meeting=meeting,
                           agenda_list=agenda_list, attendees_list=attendees_list, action_items_list=action_items_list)

@app.route("/meeting/<int:meeting_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)

    # Instantiate blank form for POST validation, but use data for GET rendering
    form = MeetingForm()

    if form.validate_on_submit(): # Handle POST request
        # Process WTForms data (which should be populated correctly from manual HTML fields)
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

        # Update DB object
        meeting.title = form.title.data
        meeting.meeting_date = form.meeting_date.data
        meeting.attendees = attendees_json_string
        meeting.agenda = agenda_json_string
        meeting.minutes = form.minutes.data
        meeting.action_items = action_items_json_string

        db.session.commit()
        flash('Your meeting has been updated!', 'success')
        return redirect(url_for('meeting_detail', meeting_id=meeting.id))

    elif request.method == 'GET': # Handle GET request (Pass populated form AND data lists)
        # Parse data lists from JSON for the template's manual rendering loops
        try: agenda_list = json.loads(meeting.agenda or '[]')
        except: agenda_list = []
        try: attendees_list = json.loads(meeting.attendees or '[]')
        except: attendees_list = []
        try: action_items_list = json.loads(meeting.action_items or '[]')
        except: action_items_list = []

        if not isinstance(agenda_list, list): agenda_list = []
        if not isinstance(attendees_list, list): attendees_list = []
        if not isinstance(action_items_list, list): action_items_list = []

        # Create form instance PRE-POPULATED with data (needed for simple fields & WTForms loop variables)
        form_data = {
            'title': meeting.title,
            'meeting_date': meeting.meeting_date,
            'attendees': attendees_list,
            'agenda_items': agenda_list,
            'minutes': meeting.minutes,
            'action_items': action_items_list
        }
        form = MeetingForm(data=form_data) # Re-assign form with populated data for GET

    # Render template for GET or invalid POST (form has data/errors, lists are for manual loops)
    return render_template('create_meeting.html', title='Edit Meeting', form=form, legend='Edit Meeting',
                           attendees_list=attendees_list,
                           agenda_list=agenda_list,
                           action_items_list=action_items_list)


@app.route("/meeting/<int:meeting_id>/delete", methods=['POST'])
@login_required
def delete_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    if meeting.author != current_user:
        abort(403)
    db.session.delete(meeting)
    db.session.commit()
    flash('Your meeting has been deleted!', 'success')
    return redirect(url_for('meetings_list'))

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

    def add_section(title, content):
        effective_width = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Arial', '', 12)
        if isinstance(content, list):
            if content:
                for item in content:
                    pdf.set_x(pdf.l_margin)
                    if isinstance(item, dict): # Action Item
                        desc = item.get('description', '')
                        assignee = item.get('assigned_to', '')
                        deadline_str = item.get('deadline', '')
                        assignee_deadline_text = ""
                        if assignee: assignee_deadline_text += f"Assigned: {assignee}"
                        if deadline_str:
                            if assignee: assignee_deadline_text += "  |  "
                            assignee_deadline_text += f"Deadline: {deadline_str}"
                        if assignee_deadline_text:
                            pdf.set_font('Arial', 'I', 10)
                            pdf.multi_cell(effective_width, 4, assignee_deadline_text)
                            pdf.set_x(pdf.l_margin)
                        pdf.set_font('Arial', '', 12)
                        pdf.set_x(pdf.l_margin + 5)
                        desc_width = effective_width - 5
                        pdf.multi_cell(desc_width, 5, f"- {desc}" if desc else "- N/A")
                        pdf.ln(3)
                    else: # Agenda / Attendee
                        pdf.multi_cell(effective_width, 5, f"- {str(item)}")
            else:
                 pdf.multi_cell(effective_width, 5, "N/A")
        else: # Minutes
            pdf.multi_cell(effective_width, 5, content if content else "N/A")
        pdf.ln(5)

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

# End of file