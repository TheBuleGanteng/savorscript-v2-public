from flask import Flask, flash, g, jsonify, make_response, redirect, render_template, request, session, url_for, url_for
import flask
print("Flask version:", flask.__version__)
from cs50 import SQL
from datetime import date, datetime, timedelta, timezone
from dotenv import load_dotenv
load_dotenv()
import DNS
from email_validator import validate_email, EmailNotValidError
from flask_mail import Mail, Message
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from helpers import login_required
from html import escape
from itsdangerous import TimedSerializer as Serializer
import os
import re
import time
from urllib.parse import unquote
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import DateField, EmailField, PasswordField, SelectField, StringField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp, StopValidation



# ------------------------------------------------------------------------------------------


app = Flask(__name__)


# --------------------------------------------------------------------------------------------


# Determine the environment and configure the database accordingly
# Configure SQLAlchemy with your SQLite database
if os.getenv('FLASK_ENV') == 'testing':
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('TEST_DATABASE_URL')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# Disable SQLAlchemy modification tracking for performance
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Create the SQLAlchemy db instance
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    name_first = db.Column(db.String(50))
    name_last = db.Column(db.String(50))
    birthdate = db.Column(db.Date)
    gender = db.Column(db.String(20))
    user_email = db.Column(db.String(320), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    pw_hashed = db.Column(db.String(80), nullable=False)
    confirmed = db.Column(db.Integer, nullable=False, default=0)
    created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

# -------------------------------------------------------------------------------------------------


# Enabling CSRF for Flask
csrf = CSRFProtect(app)


# Articulates what sources are allowed for JS and CSS, and other content.
csp_policy = {
    'default-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
    ],
    'script-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
    ],
    'style-src': [
        '\'self\'',
        'https://cdn.jsdelivr.net',
        '\'unsafe-inline\'',
    ],
    'img-src': [
        "'self'",
        "data:",  # Allows data URIs for images
    ],
    # Specifies where to log violations of this csp policy (see route below).
    'report-uri': '/csp-violation-report'
}


# Initialize Talisman with the CSP policy
talisman = Talisman(app, content_security_policy=csp_policy)


def generate_nonce():
    return os.urandom(16).hex()


# ----------------------------------------------------------------------------------------------


# Configure session to use filesystem (instead of signed cookies) (copied from CS50 wk9, Finance)
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', '0') == '1' # (Debug = 1 means debug is on)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
Session(app)
   

# ----------------------------------------------------------------------------------------


# Settings to allow for email sending
# Get the port number from the PORT environment variable (default is 10000)
port = int(os.environ.get("PORT", 10000))

# Configuring SMTP server
app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_PORT = 587,
    MAIL_USERNAME = os.getenv('MAIL_USERNAME'),
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD'),
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
))

# Initializing mailer
mail = Mail(app)


# ----------------------------------------------------------------------------------------


# Token generation for password reset
def get_reset_token(user_id):
    s = Serializer(app.config['SECRET_KEY'], salt='reset-salt')
    return s.dumps({'user_id': user_id})

def verify_reset_token(token, max_age=900):
    s = Serializer(app.config['SECRET_KEY'], salt='reset-salt')
    try:
        data = s.loads(token, max_age=max_age)
        user_id = data['user_id']
    except:
        return None
    
    user_data = User.query.filter_by(user_id=user_id).first()
    return user_data


# ----------------------------------------------------------------------------------------


def auto_database_cleanup():
    
    # Step 1: Calculate the time 24 hours ago from now
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=900)
    
    # Step 2: Run DB command to delete users that are (a) unconfirmed and (b) created before
    # cutoff time.
    User.query.filter(User.confirmed == 0, User.created < cutoff_time).delete()
    db.session.commit()


# ----------------------------------------------------------------------------------------


# Custom filter summary:
    # Custom filter 1: Strips user input.
    # Custom filter 2: Converts user input to lowercase. 

# Custom filter 1: Strip user input.
def strip_filter(input):
    return input.strip() if input else input

# Custom filter 2: Convert user input to lowercase.
def lowercase_filter(input):
    return input.lower() if input else input



# Custom validator summary:
    # Custom validator 1: Checks user input for prohibited chars.
    # Custom validator 2: Checks user input for password strength requirements.
    # Custom validator 3: Checks if user input matches username associated with session[]
    # Custom validator 4: Checks if user input matches password associated with session['user_id']
    # Custom validator 5: Checks if user input differs from password associated with session['user_id']
    # Custom validator 6: Allows birthdate to be optional w/o causing flask form validation issues
    # Custom validator 7: Checks if user input matches email address registered & active in DB.


# Custom validator 1: Ensure user input does not contain prohibited 
# characters (no prohibited chars = True).
user_input_allowed_letters = 'a-zA-Z'
user_input_allowed_numbers = '0-9'
user_input_allowed_symbols = '_*~#!+-=.\'%$ @<:/'
# Escape the symbols for safe inclusion in regex pattern
user_input_allowed_symbols_escaped = re.escape(user_input_allowed_symbols or '')
user_input_allowed_all = ''.join([user_input_allowed_letters, 
                                  user_input_allowed_numbers, 
                                  user_input_allowed_symbols_escaped])
# Regular expression pattern to match the entire string
allowed_chars_check_pattern = r'^[' + user_input_allowed_all + r']+$'
# Define function
def allowed_chars(user_input):
    if re.match(allowed_chars_check_pattern, str(user_input)):
        return True
# Define validator
def allowed_chars_validator(form, field):
    if not re.match(allowed_chars_check_pattern, field.data):
        print(f'Custom validator allowed_chars_validator failed for input: {field.data}')
        raise ValidationError(f'Invalid input for "{field.label.text}" Please ensure user inputs contain only letters, numbers, and the following symbols: {user_input_allowed_symbols}')
    else:
        return field.data
    

# Custom validator 2: Ensure user-entered password meets strength requirements.
# sufficient strength = True.
pw_req_length = 4
pw_req_letter = 2
pw_req_num = 2
pw_req_symbol = 0
# Define function
def pw_strength_check(user_input):
    if (
        len(user_input) >= pw_req_length and 
        len(re.findall(r'[a-zA-Z]', user_input)) >= pw_req_letter and 
        len(re.findall(r'[0-9]', user_input)) >= pw_req_num and
        len(re.findall(r'[^a-zA-Z0-9]', user_input)) >= pw_req_symbol):
        return True
# Define validator
def pw_strength_check_validator(form, field):
    if not pw_strength_check(field.data):
        print(f'Custom validator pw_strength_check_validator failed for input: {field.data}')
        raise ValidationError(f'Error: Invalid input for "{field.label.text}" Please ensure user inputs contain only letters, numbers, and the following symbols: {user_input_allowed_all}')
    else:
        return field.data
    

# Custom validator 3: Ensure user-entered username matches username associated with session[] 
# Define validator
def email_logged_in_validator(form, field):
    if field.data.lower() != session['user_email'].lower():
        print(f'Custom validator "email_logged_in_validator" failed for input: {field.data}')
        raise ValidationError(f'Error: Invalid input for "{field.label.text}" Please ensure email address matches currently logged-in user.')
    else:
        print(f'Custom validator "email_logged_in_validator" passed for input: {field.data}')
        return field.data


# Custom validator 4: Ensure user-entered current password matches password for 
# currently logged-in user (matches on user_id).
# Defines function:
def password_matches_existing(user_input):
    user_data = User.query.filter_by(user_id=session['user_id']).first()
    if user_data and check_password_hash(user_data['pw_hashed'], user_input):
            return True
    else:
        return False
    
# Defines validator:
def password_matches_existing_true_validator(form, field):
    if not password_matches_existing(field.data):
        print(f'Custom validator "password_matches_existing_true_validator" failed for input: {field.data}')
        raise ValidationError(f'Error: Invalid input for "{field.label.text}" Please ensure password matches that for user currently logged-in.')
    else:
        return field.data


# Custom validator 5: Ensure user-entered data DOES NOT match current password for user.
def password_matches_existing_false_validator(form, field):
    if password_matches_existing(field.data):
        print(f'Custom validator "password_matches_existing_false_validator" failed for input: {field.data}')
        raise ValidationError(f'Error: Invalid input for "{field.label.text}" Please ensure your new password does not match your old password.')
    else:
        return field.data
     

# Custom validator 6: Allow birthdate to be optional w/o causing validation issues.
class OptionalIfDate(Optional):
    """Custom validator: makes a DateField optional if no data entered"""
    def __call__(self, form, field):
        if not field.raw_data or not field.raw_data[0]:
            field.errors[:] = []
            raise StopValidation()


# Custom validator 7: Checks if user-inputted email and password match an active user in DB. 
# Defines function (returns True if passed)
def user_email_registered_check(user_inputted_email, user_inputted_password):
    user_data = User.query.filter_by(user_email=user_inputted_email).first()
    if user_data and user_data.confirmed == 1 and check_password_hash(user_data.pw_hashed, user_inputted_password):
        print(f'running user_email_registered_check(user_inputted_email, user_inputted_password)... validation passed and function returned True')
        return True
    else:
        print(f'running user_email_registered_check(user_inputted_email, user_inputted_password)... validation failed and function returned False. user inputted valid email address was: { user_inputted_email }, and user_data.confirmed was: { user_data.confirmed }, and check_password_hash(user_data.pw_hashed, user_inputted_password) was: { check_password_hash(user_data.pw_hashed, user_inputted_password) }')
        return False
        


# ------------------------------------------------------------------------------------


# Defining form classes for use with Flask-WTF
class LoginForm(FlaskForm):
    user_email = StringField('Email', filters=[strip_filter, lowercase_filter], validators=[DataRequired(), Email(), allowed_chars_validator])
    password = PasswordField('Password', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator])
    submit = SubmitField('Log In')
  

class ProfileForm(FlaskForm):
    name = StringField('Name:', render_kw={'readonly': True})
    name_first_input = StringField('New first name:', filters=[strip_filter], validators=[Optional(), allowed_chars_validator])
    name_last_input = StringField('New last name:', filters=[strip_filter], validators=[Optional(), allowed_chars_validator])
    username_old =  StringField('Username:', render_kw={'readonly': True})
    username =  StringField('New username:', filters=[strip_filter], validators=[Optional(), allowed_chars_validator])
    gender =  StringField('Gender:', render_kw={'readonly': True})
    gender_input =  SelectField('New gender:', 
                                choices=[('', 'Select gender'), ('female', 'Female'), ('male', 'Male'), ('undisclosed', "I'd rather not say")],
                                validators=[Optional()],
                                render_kw={"aria-label": "Default select example", "onchange": "enableSubmitButton()"}
    )
    birthdate = DateField('Birthdate:', 
                                format='%Y-%m-%d', 
                                validators=[OptionalIfDate()])
    birthdate_input = DateField('New birthdate:', 
                                format='%Y-%m-%d', 
                                validators=[OptionalIfDate()])
    user_email = EmailField('Email address:', render_kw={'readonly': True})
    submit_button = SubmitField('Save changes')

class PasswordChangeForm(FlaskForm):
    user_email =  EmailField('Email address:', filters=[strip_filter, lowercase_filter], validators=[DataRequired(), Email(), allowed_chars_validator, email_logged_in_validator], render_kw={'required': True})
    password_old = PasswordField('Current password:', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator, password_matches_existing_true_validator], render_kw={'required': True})
    password =  PasswordField('New password:', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator, pw_strength_check_validator, password_matches_existing_false_validator], render_kw={'required': True})
    password_confirmation = PasswordField('New password confirmation:', filters=[strip_filter], validators=[DataRequired(), EqualTo('password', message='New password confirmation must match the new password.'), allowed_chars_validator], render_kw={'required': True})
    submit_button = SubmitField('Submit')

class PasswordResetRequest(FlaskForm):
    user_email =  EmailField('Email address:', filters=[strip_filter, lowercase_filter], validators=[DataRequired(), Email(), allowed_chars_validator], render_kw={'required': True})
    submit_button = SubmitField('Submit')

class PasswordResetForm(FlaskForm):
    password =  PasswordField('New password:', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator, pw_strength_check_validator, password_matches_existing_false_validator], render_kw={'required': True})
    password_confirmation =  PasswordField('New password confirmation:', filters=[strip_filter], validators=[DataRequired(), EqualTo('password', message='New password confirmation must match the new password.'), allowed_chars_validator, pw_strength_check_validator], render_kw={'required': True})
    submit_button = SubmitField('Submit')


class RegisterForm(FlaskForm):
    name_first = StringField('First name', filters=[strip_filter], validators=[Optional(), allowed_chars_validator])
    name_last = StringField('Last name', filters=[strip_filter], validators=[Optional(), allowed_chars_validator])
    gender = SelectField('Gender', choices=[
    ('undisclosed', 'Select gender (optional)'),
    ('female', 'Female'),
    ('male', 'Male'),
    ('undisclosed', "I'd rather not say")
    ], validators=[Optional()], default='undisclosed', render_kw={"class": "form-select"})
    birthdate = DateField('Birthdate', validators=[Optional()])
    username = StringField('Username', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator], render_kw={'required': True})
    user_email = EmailField('Email address', filters=[strip_filter, lowercase_filter], validators=[DataRequired(), Email(), allowed_chars_validator], render_kw={'required': True})
    password = PasswordField('Password', filters=[strip_filter], validators=[DataRequired(), allowed_chars_validator, pw_strength_check_validator])
    password_confirmation = PasswordField('Password confirmation', filters=[strip_filter], validators=[DataRequired(), EqualTo('password', message='New password confirmation must match the new password.'), allowed_chars_validator], render_kw={'required': True})
    submit_button = SubmitField('Register')


#-------------------------------------------------------------------------------------
    

@app.before_first_request
def create_tables():
    db.create_all()


# ----------------------------------------------------------------------------------------


@app.route('/')
@login_required
def index():

    # Test for session persistance across routes
    print(f'Running / route.... session is: {session}')

    # Render index.html and pass in the values in the portfolio pull and for cash.
    return render_template('index.html')



# ----------------------------------------------------------------------------------------


# Route checks if email address is of a valid format and if it is already registered 
# in real-time and feeds into HTML via the JS function jsEmailValidation()
@app.route('/check_email_availability', methods=['POST'])
def check_email_availability():
    print(f'running /check_email_availability route...')
    
    # Get the user-submitted email address from the POST request data
    user_email = request.form.get('user_email').lower()
    
    # Perform the database query to check username availability 
    # (note: ilike is a case-insensitive match).
    user_email_db_pull = User.query.filter(User.user_email.ilike(user_email)).first()
            
    print(f'running /email_check_availability... the value of user_email is: {user_email}')
    print(f'running /email_check_availability... the value of user_email_db_pull is: {user_email_db_pull}')

    if user_email_db_pull is not None:
        print(f'running /check_email_availability... none email address found for user-inputted email address: {user_email}')
        email_check_result = 'already_registered'
    else:
        email_check_result = 'available'
        print(f'running /check_email_availability... no email address found in DB for user-inputted email address: {user_email}')

    print(f'running /check_email_availability... email_check_result is: {email_check_result}')
    return jsonify({'email_check_result': email_check_result})


# -----------------------   -----------------------------------------------------------------


# Route checks for username availability in real-time and feeds into HTML 
# via the JS function jsUsernameValidation()
@app.route('/check_username_availability', methods=['POST'])
def check_username_availability():
    print(f'running /check_username_availability route...')
    print(f'running /check_username_availability route... request headers is: {request.headers}')
    print(f'running /check_username_availability route... CSRF token in flask is: {request.headers.get("X-CSRFToken")}')
    
    # Get the username from the POST request data
    username = request.form.get('username')
    
    # Perform the database query to check username availability
    username_db_pull = User.query.filter(User.username.ilike(username)).first()
    
    print(f'running /check_username_availability... the value of user-inputted username is: { username }')
    print(f'running /check_username_availability... the value of username_db_pull is: { username_db_pull }')

    if username_db_pull is None:
        print(f'running /check_username_availability... no username found for user-inputted username: { username }')
        available = 'available'
    else:
        print(f'running /check_username_availability... no username found for user-inputted username: {username}')
        available = 'unavailable'

    # Return a JSON response indicating availability
    print(f"running /check_username_availability route on username: { username }... available is: { available }")
    return jsonify({ 'available': available })


# ----------------------------------------------------------------------------------------


# Route checks if user-entered email address meets standards.
@app.route('/check_password_strength', methods=['POST'])
def check_password_strength():
    # Get the username from the POST request data
    password = request.form.get('password')
    password_confirmation = request.form.get('password_confirmation')
    
    # Initiate variable to track number of checks passed
    checks_passed = []
    checks_passed_confirmation = []

    # Perform strength check on password
    if(password):
        if len(password) >= pw_req_length:
            checks_passed.append('pw_reg_length')
        if len(re.findall(r'[a-zA-Z]', password)) >= pw_req_letter:
            checks_passed.append('pw_req_letter')
        if len(re.findall(r'[0-9]', password)) >= pw_req_num:
            checks_passed.append('pw_req_num')
        if len(re.findall(r'[^a-zA-Z0-9]', password)) >= pw_req_symbol:
            checks_passed.append('pw_req_symbol')

    # Perform strength check on password_confirmation
    if(password_confirmation):    
        if len(password_confirmation) >= pw_req_length:
            checks_passed_confirmation.append('pw_reg_length')
        if len(re.findall(r'[a-zA-Z]', password_confirmation)) >= pw_req_letter:
            checks_passed_confirmation.append('pw_req_letter')
        if len(re.findall(r'[0-9]', password_confirmation)) >= pw_req_num:
            checks_passed_confirmation.append('pw_req_num')
        if len(re.findall(r'[^a-zA-Z0-9]', password_confirmation)) >= pw_req_symbol:
            checks_passed_confirmation.append('pw_req_symbol')
    
    if password == password_confirmation:
        confirmation_match = True
    else:
        confirmation_match = False

    print(f'checks_passed_confirmation is: {checks_passed_confirmation}')
    print(f'password is: {password}')
    print(f'password_confirmation is: {password_confirmation}')
    print(f'confirmation_match is: {confirmation_match}')

    # Return a JSON response indicating availability
    return jsonify({'checks_passed': checks_passed, 'checks_passed_confirmation': checks_passed_confirmation, 'confirmation_match': confirmation_match} )


# ----------------------------------------------------------------------------------------



@app.route('/csp-violation-report', methods=['POST'])
@csrf.exempt
def csp_report():
    if request.content_type in ['application/csp-report', 'application/json']:
        report = request.get_json(force=True)
        # Process the report
        # Log the report for debugging
        print(f"CSP Report: {report}")
    else:
        # Handle unexpected content-type
        print(f"Unexpected Content-Type: {request.content_type}")
        return 'Unsupported Media Type', 415
    return '', 204


# ----------------------------------------------------------------------------------------



@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f'Running /login route... route started')
    print(f'Running /login route... session is:{session}')

    nonce = generate_nonce()
    print(f'Running /login route... nonce is:{nonce}')

    # Step 1: Display Flask-WTF LoginForm (defined above)
    form = LoginForm()
    
    # Step 2: Store CSRF token and flash temp message, if any.
    temp_flash = session.get('temp_flash')
    csrf_token = session.get('csrf_token')
    session.clear()
    if temp_flash:
        flash(temp_flash)
    if csrf_token:
        session['csrf_token'] = csrf_token

    # Step 3: Do the following if user submission is via post...
    if request.method == 'POST':

        # Step 3.1: Do the following if user submission is via post and passes form validation...
        if form.validate_on_submit():
        
            # Step 3.1.1: Pull in user-entered data from form.
            user_inputted_email = form.user_email.data.lower()
            user_inputted_password = form.password.data

            # Step 3.1.2: Check if (a) user entered email is valid in DB and (b) if user-entered
            # email and password are a valid match in DB (True if passes)
            if not user_email_registered_check(user_inputted_email, user_inputted_password):
                print(f'Running /login route... encountered error 3.1.2')
                session['temp_flash'] = 'Error 3.1.2: Invalid username or password. If you have not yet registered, please click the link below. If you have recently requested a password reset, check your email inbox and spam folders.'
                return redirect(url_for('login'))

            
            # Step 3.1.5: Validation has passed secondary validation. Log user in by setting session equal to user data.
            # Step 3.1.5.1: Iterate across all the keys in user_data, except the password, which 
            # is excluded for security reasons.
            
            user_data = User.query.filter_by(user_email=user_inputted_email).first()
            
            
            user_data = db.execute(
                'SELECT * FROM users WHERE user_email = ?', (user_inputted_email))
            user_data = user_data[0]
            
            for key in user_data:
                if key != 'pw_hashed':
                    session[key] = user_data[key]
                    
            print(f'Running /login route...session established. Session is: {session}.')

            # Step 3.1.5.2: User is logged in. Flash message and redirect user to index.
            print(f'Running /login route... user logged in successfully and redirected to index.')
            flash('User login successful')
            return redirect(url_for('index'))
        else:
            # Step 3.2: Do the following if submission is via post, but fails validate_on_submit.
            print(f'Running /login route... encountered error 3.2')
            session['temp_flash'] = 'Error 3.1: Invalid username or password. If you have not yet registered, please click the link below.'
            print("Session after setting temp_flash:", session)
            return redirect(url_for('login'))
    else:   
        # Step 4: If not submitted via POST, display the form.
        print(f'Running /login route... user arrived via GET')
        response = make_response(render_template('login.html', form=form, nonce=nonce))
        print(f'response.headers is: {response.headers}')  # Debugging line
        return response



# ----------------------------------------------------------------------------------------


@app.route('/logout')
def logout():
    '''Log user out'''
    print(f'running /logout route...')

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    session['temp_flash'] = 'User logged out'
    return redirect(url_for('login'))


# ----------------------------------------------------------------------------------------

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():

    # Test for session persistance across routes
    print(f'Running /profile route..., session is: {session}')

    # Step 1: Create an instance of the ProfileForm
    form = ProfileForm()

    # Step 2: If the data is submitted via post, do the following...
    if request.method == 'POST':

        # Step 2.1: Check user inputs against form validation.
        if form.validate_on_submit():
            # Step 2.1.1: Pull in data submitted by the user via the form
            user_data_submitted = {
                'name_first': form.name_first_input.data,
                'name_last': form.name_last_input.data,
                'username': form.username.data,
                'gender': form.gender_input.data,
                'birthdate': form.birthdate_input.data
            }

            # Step 2.1.2: If a value in user_data is blank (e.g. user didn't update that field),
            # then repopulate that value with the existing value in session.
            # Step 2.1.2.1: Iterate over the key-value pairs in user_data
            for key in user_data_submitted.keys():
                # Step 2.1.2.2: Check if the value in user_data is empty
                if user_data_submitted[key] == '':
                    # Step 2.1.2.3: If empty, update it with the value from session, if available
                    user_data_submitted[key] = session.get(key, session[key])

            # Step 2.1.3: Prepare and run SQL query (note SQL injection vulnerability)
            query = 'UPDATE users SET name_first = ?, name_last = ?, username = ?, gender = ?, birthdate = ? WHERE user_id = ?'
            db.execute(query, user_data_submitted['name_first'], user_data_submitted['name_last'], user_data_submitted['username'], user_data_submitted['gender'], user_data_submitted['birthdate'], session['user_id'])
            
            # Step 2.1.4: Update session by iterating across all the keys in user_data_submitted, 
            # except the password, which is excluded for security reasons.
            for key in user_data_submitted:
                if key != 'pw_hashed':
                    session[key] = user_data_submitted[key]

            flash('Profile updated successfully.')
            return redirect(url_for('profile'))
        
        # Step. 2.2: If validation on form fails, display error message and redirect to profile.
        else:
            print(f'Running /profile route... form.errors is: {form.errors}')
            flash('There were errors in your form. Please see the error messages below to correct your input.')
            return render_template('profile.html', form=form)
            
    # Step 3: Handle GET request.
    else:   
        
        # Step 3.1: Pass data from session[] to the form.
        # Note conversion of birthdate from str to date. This is req. for flask-wtf
        # form compatibility.
        name_first = session.get('name_first', '') or ''
        name_last = session.get('name_last', '') or ''
        form.name.data = escape((name_first + ' ' + name_last).strip())
        form.username_old.data = escape(session.get('username', '') or '')
        form.gender.data = escape(session.get('gender', '') or '')
        if session.get('birthdate'):
            birthdate = session.get('birthdate')
            if isinstance(birthdate, date):
                form.birthdate.data = birthdate
            else:
                form.birthdate.data = datetime.strptime(birthdate, '%Y-%m-%d')
        else:
            form.birthdate.data = None
        form.user_email.data = escape(session.get('user_email', '') or '')
        return render_template('profile.html', form=form)
   
    
   
# ----------------------------------------------------------------------------------------


@app.route('/pw_change', methods=['GET', 'POST'])
@login_required
def pw_change():
    
    # Test for session persistance across routes
    print(f'Running /pw_change route... session is: {session}')

    # Step 1: Create an instance of the ProfileForm
    form = PasswordChangeForm()

    # Step 2: If the data is submitted via post, do the following...
    if request.method == 'POST':
        print(f'Running /pw_change route... user submitted data via post.')
        print(f"Running /pw_change route... form data is: {request.form}")

        # Step 2.1: Check user inputs against form validation.
        if form.validate_on_submit():
            print(f'Running /pw_change route... user submitted data via post and data passed class validation')

            # Step 2.1.1: Pull in data submitted by the user via the form
            password = form.password.data

            # Step 2.1.3: Hash the new password
            password_hashed = generate_password_hash(password)

            # Step 2.1.4: Insert the username and hashed password into their corresponding columns in the DB.
            db.execute(
                'UPDATE users SET pw_hashed = (?) WHERE user_id = (?)', password_hashed, session['user_id']
            )

            # Step 2.1.5: Flash an indication to the user that the password pw_change 
            # was successful and then redirect to index.
            print(f'Running /pw_change route... route completed successfully')
            flash('Password change successful!')
            return redirect(url_for('index'))
        
        # Step 2.2: Show errors if submitted via post, but user input fails validation.
        else:
            print(f'Running /pw_change route... form validation errors: {form.errors}')
            flash('There were errors in your form, please see the error messages below to correct your input.')
            return render_template('pw_change.html',
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)
    
    else:
        print(f'Running /pw_change route... user accessed route via get')
        return render_template('pw_change.html',
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)



# ----------------------------------------------------------------------------------------


@app.route('/pw_reset_req', methods=['GET', 'POST'])
def pw_reset_req():

    # Test for session persistance across routes
    print(f'Running /pw_reset_req route... session is: {session}')

    # Step 1: Create an instance of the PasswordResetRequest form.
    form = PasswordResetRequest()

    # Step 2: If the user submitted via post, do the following...
    if request.method == 'POST':
        print(f'Running /pw_reset_req route... user submitted data via post.')
        print(f"Running /pw_reset_req route... form data is: {request.form}")

        # Step 2.1: If the user submitted via post and the input passes form validation,
        # do the following...
        if form.validate_on_submit():
            print(f'Running /pw_reset_req route... user submitted data via post and data passed class validation')

            # Step 2.1.1: Pull in data submitted by the user via the form
            pw_reset_email = form.user_email.data
            print(f'Running /pw_reset_req route... pw_reset_email is: {pw_reset_email}.')

            # Step 2.1.2: Do DB pull, trying to match on user-provided email.
            user_data = db.execute(
                'SELECT * FROM users WHERE user_email = ?', (pw_reset_email)
            )
            print(f'Running /pw_reset_req route... user_data is: {user_data}.')

            # Step 3.1.3: If no match, show success message anyway and redirect to login.
            if len(user_data) != 1:
                print(f'Running /pw_reset_req route... Error 3.1.3: User tried to reset password using unregistered email address. User data is: {user_data}.')
                session['temp_flash'] = 'Reset email sent. Please do not forget to check your spam folder!' 
                return redirect(url_for('login'))

            # Checks have passed. Proceed to generate and send token via email.
            # Step 3.1.4: Take first record in user_data.
            user_data = user_data[0]
            print(f'Running /pw_reset_req route... user_data[0] is: {user_data}.')
            
            # Step 3.1.5: Generate a token for the user
            token = get_reset_token(user_data['user_id'])
            print(f'Running /pw_reset_req route... token generated.')
                
            # Step 3.1.6: Set variables for email to be sent.
            username = user_data['username']
            sender = 'info@mattmcdonnell.net'
            subject = 'Password reset from SavorScript'
            body = f'''Dear {username}: to reset your password, please visit the following link: 
{url_for('pw_reset_new', token=token, _external=True)}

If you did not make this request, you may ignore it.

Thank you,
Team SavorScript'''
            
            # Step 3.1.7: Send email.
            msg = Message(subject=subject, body=body, sender=sender, recipients=[pw_reset_email])
            mail.send(msg)
            print(f'Running /pw_reset_req route... reset email sent to email address: {pw_reset_email}.')

            # Step 3.1.8: Flash success message and redirect to index.
            print(f'Running /pw_reset_req route... flashed success message and redirected user to index.')
            session['temp_flash'] = 'Reset email sent. Please do not forget to check your spam folder!'    
            return redirect(url_for('login'))
        
        # Step 3.2: Do the following if user submitted via POST, but failed form validation... 
        else:
            print(f'Running /pw_reset_req route... form validation errors: {form.errors}')
            flash('There were errors in your form, please see the error messages below to correct your input.')
            return render_template('pw_reset_req.html',
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)
    else:
        print(f'Running /pw_reset_req route... user accessed route via get')
        return render_template('pw_reset_req.html',
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)




# ----------------------------------------------------------------------------------------



@app.route('/pw_reset_new/<token>', methods=['GET', 'POST'])
def pw_reset_new(token):
    
    # Step 1: Take token in url and decode it.
    # Step 1.1: Decode the url token to be processed further
    decoded_token = unquote(token)
    # Step 1.2: Take that decoded token and tell me what user generated 
    # it by returning that user's user_id.
    user = verify_reset_token(decoded_token)
    print(f'Running /pw_reset_new route... user is: {user}.')
    
    session['user_id'] = user['user_id']
    print(f'Running /pw_reset_new route... session["user_id"] is: {session["user_id"]}.')

    # Step 1: Create an instance of the PasswordResetRequest form.
    form = PasswordResetForm()

    # Step 2: If the user submitted via post, do the following...
    if request.method == 'POST':
        print(f'Running /pw_reset_new route... user submitted data via post.')

        # Step 2.1: If the user submitted via post and the input passes form validation,
        # do the following...
        if form.validate_on_submit():
            print(f'Running /pw_reset_new route... user submitted data via post and data passed class validation')

            # Step 2.1.1: If token isn't legit, throw error and redirect user.
            if not session:
                print(f'Running /pw_reset_new route... Error 2.1.1: Invalid token.')
                session['temp_flash'] = 'Error 2.1.1: Invalid or expired reset link. Please login or re-request your password reset.'    
                return redirect(url_for('login'))

            # Step 2.1.2: Pull in data submitted by the user via the form
            password = form.password.data
            print(f'Running /pw_reset_new route... pulled in password_new.')

            # Step 2.1.3: Hash the new password.
            pw_hashed = generate_password_hash(password)
            print(f'Running /pw_reset_new route... new pw_hashed generated.')
        
            # Step 2.1.4: Insert the new username and hashed password into their 
            # corresponding columns in the DB.
            db.execute(
            'UPDATE users SET pw_hashed = ? WHERE user_id = ?', pw_hashed, session['user_id']
            )
            print(f'Running /pw_reset_new route... updated DB with new_pw_hashed for session["user_id"]: {session["user_id"]}')
            

            # Step 2.1.5: Inform the user that the password was changes successfully.
            print(f'Running /pw_reset_new route... flashed success message and redirected to index.')
            session['temp_flash'] = 'Success! Password changed successfully.'
            return redirect(url_for('login'))
        
        # Step 2.2: If the user submitted via post and the input fails form validation,
        # do the following...
        else:
            print(f'Running /pw_reset_new route... form validation errors: {form.errors}')
            flash('There were errors in your form, please see the error messages below to correct your input.')
            return render_template('pw_reset.html',
                               token=token,
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)
    else:
        print(f'Running /pw_reset_new route... user accessed route via get')
        return render_template('pw_reset.html',
                               token=token,
                               form=form,
                               pw_req_length=pw_req_length, 
                               pw_req_letter=pw_req_letter, 
                               pw_req_num=pw_req_num, 
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols)



# ----------------------------------------------------------------------------------------


@app.route('/register', methods=['GET', 'POST'])
def register():
    print(f'Running /register route... route started')
    print(f'Running /register route... session is:{session}')

    # Step 1: Display Flask-WTF RegisterForm (defined above)
    form = RegisterForm()
    

    # Step 2: Flash temp message, if any.
    temp_flash = session.get('temp_flash')
    csrf_token = session.get('csrf_token')
    session.clear()
    if temp_flash:
        flash(temp_flash)
    if csrf_token:
        session['csrf_token'] = csrf_token

    # Step 3: Handle user submission that is (a) via post and (passes class-imposed filters).
    if request.method == 'POST':
        
        # Step 3.1: Handle submission via post that passes the classes' validation.
        if form.validate_on_submit():
            
            # Step 3.1.2: Additional validation: Check if user-provided username is already taken.
            duplicates_username = db.execute(
            'SELECT * FROM users WHERE LOWER(username) = LOWER(?)', form.username.data
            )
            if len(duplicates_username) > 0:
                print('Running /register route... Step 3.1.2 failed')
                session['temp_flash'] = f'Error 3.1.2: Username is already registered. Please select a different username or log in if you are already registered.'
                return redirect(url_for('register'))

            # Step 3.1.3: Additional validation: Check if user-provided email address is already registered. 
            duplicates_user_email = db.execute(
                'SELECT * FROM users WHERE user_email = ?', form.user_email.data
            )
            if len(duplicates_user_email) > 0:
                print('Running /register route... Step 3.1.3 failed')
                session['temp_flash'] = 'Error 3.1.3: Email address is already registered. Please log in or reset your password via the links below.'
                return redirect(url_for('register'))
            
            # All validation passed: proceed with registration. 
            # Step 3.1.4: Hash the user-inputted password.
            pw_hashed = generate_password_hash(form.password.data)
            
            # Step 3.1.5: Insert the new user's data into the DB (note that confirmed is initially set to 0)
            query = 'INSERT INTO users (name_first, name_last, birthdate, gender, user_email, username, pw_hashed, confirmed, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            db.execute(query, form.name_first.data, form.name_last.data, form.birthdate.data, form.gender.data, form.user_email.data, form.username.data, pw_hashed, 0, datetime.now(timezone.utc))

            # 3.1.6: Perform DB query to get the DB-generated user_id for this user (needed for token)
            user_data = db.execute('SELECT * FROM users WHERE user_email = ?', form.user_email.data)
            user_data = user_data[0]
            user_id = user_data['user_id']

            # Step 3.1.7: Generate a token associated with the updated user's email address.
            token = get_reset_token(user_id)
                
            # Step 3.1.8: Set variables for email to be sent.
            username = user_data['username']
            sender = 'info@mattmcdonnell.net'
            recipients=[user_data['user_email']]
            subject = 'Confirm your registration with SavorScript'
            body = f'''Dear {username}: to confirm your registration with SavorScript, please visit the following link: 
{url_for('register_confirmation', token=token, _external=True)}

Please note that this link will expire in 10 minutes.

Thank you,
Team SavorScript'''
            
            # Step 3.1.9: Send email.
            msg = Message(subject=subject, body=body, sender=sender, recipients=recipients)
            mail.send(msg)  
        
            # Step 3.1.10: Flash message and redirect to login.
            session['temp_flash'] = 'We have sent you an email to confirm your registration with SavorScript. Please do not forget to check your spam folder!'    
            return redirect(url_for('login'))
        
        # Step 3.2: Do the following if user submits via post, but input fails validators.
        else:
            print('Running /register route... Step 3.2 failed')
            session['temp_flash'] = 'There were errors in your form. Please see the error messages below to correct your input.'    
            return render_template('register.html',
                               form=form, 
                               pw_req_length=pw_req_length,
                               pw_req_letter=pw_req_letter,
                               pw_req_num=pw_req_num,
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols,
                               )

    # Step 4: Do the following if user arrives via GET.
    else:
        csrf_token = generate_csrf()
        return render_template('register.html',
                               form=form, 
                               pw_req_length=pw_req_length,
                               pw_req_letter=pw_req_letter,
                               pw_req_num=pw_req_num,
                               pw_req_symbol=pw_req_symbol,
                               user_input_allowed_symbols=user_input_allowed_symbols,
                               )



# ----------------------------------------------------------------------------------------



@app.route('/register_confirm<token>', methods=['GET', 'POST'])
def register_confirmation(token):

    # Step 1: Decoding of url token
    # Step 1.1: Decode the url token to be processed further
    decoded_token = unquote(token)

    # Step 1.2: Take that decoded token and tell me what user_data dict generated 
    # it by returning that user's user_id.
    user = verify_reset_token(decoded_token)
    print(f'running /user_confirmation... user is: {user}')
    
    # Step 2: If lands on page w/o correct url token, flash an error and redirect to login.
    if not user:
        # Step 2.1: Decode the token, ignoring expiration. This is done to retrieve the user_id.
        s = Serializer(app.config['SECRET_KEY'], salt='reset-salt')
        try:
            data = s.loads(token, max_age=None)
            user_id = data['user_id']
        except:
            user_id = None

        # Step 2.2: If the user_id is extracted, use it to delete that user from the DB.
        # This is done to avoid stale, unconfirmed users from populating the DB.
        if user_id:
            # Step 2.2.1: Delete the unconfirmed user record, flash error, and redirect to login. 
            db.execute('DELETE FROM users WHERE user_id = ? AND confirmed = 0', user_id)
            session['temp_flash'] = 'Error 2.2.1: Invalid or expired registration link. Your registration has been cancelled. Please re-register.'    
            return redirect(url_for('login'))
    
    # Step 3: If user lands on page w/ correct url token, proceed with user creation.
    else:
        # Step 3.3: Do DB pull matching on user_email from token.
        user_data = db.execute('SELECT * FROM users WHERE user_id = ?', user['user_id'])
        
        # Step 3.4: If user's email is not in db, throw error and redirect to register.
        if len(user_data) != 1:
            flash('Error 3.4: No registration found. Please complete the registration form below.')
            return redirect(url_for('register'))
                
        # Step 3.5: If user's email is in db and user is confirmed, throw error and redirect to login.
        user_data = user_data[0]
        if user_data['confirmed'] == 1:
            session['temp_flash'] = 'Error 3.5: User account already confirmed, please log in using your email and password. You may request a password reset via the link below, if needed.'
            return redirect(url_for('login'))
        
        # Step 3.6: Validation steps above have passed, proceed to update user's 
        # status to confirmed in DB. Note that the 1 below is not user input and thus
        # does not need to be parameterized to protect against SQL injection. 
        db.execute('UPDATE users SET confirmed = 1 WHERE user_id = ?', user['user_id'])
        
        # Step 3.3: Set session to the user.data array (ex pw), effectively logging the user in.
        # Step 3.3.2: Iterate across all the keys in user_data, except the password, which 
        # is excluded for security reasons.
        for key in user_data:
            if key != 'pw_hashed':
                session[key] = user_data[key]
                
        print(f'running /user_confirmation...  session est via reg confirm link: {session}')
        
        # Step 3.3: Pause, flash message and redirect to login
        time.sleep(3)
        flash('Registration is confirmed. Welcome to SavorScript!')
        return redirect(url_for('index'))

# ----------------------------------------------------------------------------------------


if __name__ == '__main__':
    app.run(debug=True)
