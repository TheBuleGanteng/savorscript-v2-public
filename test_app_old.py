from app import app, db, User
from datetime import date
from flask import url_for, Flask
import os
import pytest
import re
from flask_sqlalchemy import SQLAlchemy
import shutil
from unittest.mock import patch, MagicMock
import uuid
from werkzeug.security import generate_password_hash


# Function to create a Flask app configured for testing
def create_test_app():
    # Set environment variables for testing
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///savorscript_test.sqlite'
    # other environment variables as needed

    app = Flask(__name__)
    app.config.from_mapping(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=os.environ['SQLALCHEMY_DATABASE_URI'],
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )

    db = SQLAlchemy(app)
    return app, db

# Setup and teardown of the test database
@pytest.fixture(autouse=True)
def setup_test_database():
    test_app, db = create_test_app()
    with test_app.app_context():
        db.create_all()  # Create all tables for the test database
        yield db
        db.drop_all()  # Drop all tables after the test
        db.session.remove()



# Setup steps summary: 
# Setup step 1: Defines function to create a test user in the DB where confirmed = 1.
# Setup step 2: Defines function to delete the test test user
# Setup step 3: Defines function to create an UNCONFIRMED test user in the DB where confirmed = 0
# Setup step 4: Defines function to delete the unconfirmed test user
# Setup step 5: Create an instance of app.py for testing.
# Setup step 6: Defines function to clear the users table
# Setup step 7: Declare global variable for test number


#Setup step 1: Defines function to create a test user in the DB where confirmed = 1
def insert_test_user():
    with app.app_context():
        test_user_email = f'{uuid.uuid4()}@mattmcdonnell.net'
        test_password_unhashed = 'GLBMjKJ3qphUodwvqyF!+-='
        test_password_hashed = generate_password_hash(test_password_unhashed)
        # Create a new User instance
        test_user = User(
            name_first="Test_Name_First",
            name_last="Test_Name_Last",
            birthdate=date(1990, 1, 1),
            gender="male",
            user_email=test_user_email,
            username="TestUser",
            pw_hashed=test_password_hashed,
            confirmed=1
        )
        # Add the new user to the session and commit it
        db.session.add(test_user)
        db.session.commit()
        # Retrieve the inserted user's data
        user_data_test_user = User.query.filter_by(user_email = test_user_email).first()
        # Take the first row    
        if user_data_test_user:
            user_data_test_user = user_data_test_user.as_dict()
            # Append the unhashed test password to the user_data_test_user 
            # dict (done for easier testing).
            user_data_test_user['pw_unhashed'] = test_password_unhashed
            return user_data_test_user
        else:   
            user_data_test_user = None
        return user_data_test_user


# Setup step 2: Defines function to delete the test test user
def delete_test_user(user_email):
    with app.app_context():
        user_data_test_user = User.query.filter_by(user_email = user_email).first()
        if user_data_test_user:
            db.session.delete(user_data_test_user)
            db.session.commit()
        else:
            print(f'running delete_test_user(user_email)... no user_data_test_user found in DB.')
        

# Setup step 3: Defines function to create an UNCONFIRMED test user in the DB where confirmed = 0
def insert_test_user_unconfirmed():
    with app.app_context():
        # Set unregistered user test email address.
        test_user_email = f'{uuid.uuid4()}@mattmcdonnell.net'
        test_password_unhashed = 'GLBMjKJ3qphUodwvqyF!+-='
        test_password_hashed = generate_password_hash(test_password_unhashed)
        # Create a new User instance
        test_user = User(
            name_first="Test_Name_First",
            name_last="Test_Name_Last",
            birthdate=date(1990, 1, 1),
            gender="male",
            user_email=test_user_email,
            username="TestUser",
            pw_hashed=test_password_hashed,
            confirmed=0,
        )
        # Add the new user to the session and commit it
        db.session.add(test_user)
        db.session.commit()
        # Retrieve the inserted user's data
        user_data_unconfirmed_user = User.query.filter_by(user_email = test_user_email).first()
        # Take the first row    
        if user_data_unconfirmed_user:
            user_data_unconfirmed_user = user_data_unconfirmed_user.as_dict()
            # Append the unhashed test password to the user_data_unconfirmed_user 
            # dict (done for easier testing).
            user_data_unconfirmed_user['pw_unhashed'] = test_password_unhashed
            return user_data_unconfirmed_user
        else:
            print('running insert_test_user_unconfirmed... failed to create a test_user_unconfirmed')
            user_data_unconfirmed_user = None


# Setup step 4: Defines function to delete the unconfirmed test user
def delete_test_user_unconfirmed(user_email):
    with app.app_context():
        user_data_unconfirmed_user = User.query.filter_by(user_email = user_email).first()
        if user_data_unconfirmed_user:
            db.session.delete(user_data_unconfirmed_user)
            db.session.commit()
        else:
            print(f'running delete_test_user_unconfirmed(user_email)... no user_data_unconfirmed_user found in DB.')


# Setup step 5: Create an instance of app.py for testing.
@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


# Setup step 6: Define function to clear the users table
def clear_users_table():
    """Function to clear the 'users' table."""
    with app.app_context():
        # Query all records from the 'users' table and delete them
        User.query.delete()
        db.session.commit()



# Setup step 7: Declare global variable for test number
test_number = 0


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /login
# Summary: 
# Test 1: Happy path (valid email+valid pw)
# Test 2: User attempts to log in w/o valid CSRF token.
# Test 3: No CSP headers in page
# Test 4: No email entered
# Test 5: No PW entered
# Test 6: No email + no PW entered
# Test 7: Undeliverable email entered
# Test 8: Unregistered email
# Test 9: Registered email + wrong pw
# Test 10: Unregistered email + wrong pw
# Test 11: User tries to log in w/ unconfirmed account


# /login Test 1: Happy Path: user logs in w/ valid email address + valid password --> user redirected to / w/ success message.
def test_login_happy_path(client):
    #db = setup_test_database()
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)

    assert response.request.path == '/'
    clear_users_table()

# /login Test 2: User attempts to log in w/o valid CSRF token.
def test_login_missing_CSRF(client):
    #db = setup_test_database()
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': 'invalid_token',
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)

    assert response.request.path == '/login'
    clear_users_table()


# /login Test 3: Tests for presence of CSP headers in page.
def test_login_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/login')
    assert response.status_code == 200

    # Check if CSP headers are set correctly in the response
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None


# /login Test 4: User does not submit email address
def test_login_without_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': '',
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 5: User does not submit PW
def test_login_without_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': '',
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 6: User does not submit username or password  --> is redirected 
# to /login and flashed message.
def test_login_without_email_without_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': '',
        'password': '',
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()


# /login Test 7: User enters undeliverable email address.
def test_login_undeliverable_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': 'matt',
        'password': test_user['pw_unhashed'],
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 8: User tries to log in w/ unregistered email address + correct PW
def test_login_with_unregistered_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': 'unregistered@mattmcdonnell.net',
        'password': test_user['pw_unhashed'],
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 9: User tries to log in w/ registered email address + invalid PW
def test_login_with_invalid_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': 'InvalidPassword',
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 10: User tries to log in w/ unregistered email address + invalid PW
def test_login_with_invalid_username_invalid_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': 'unregistered@mattmcdonnell.net',
        'password': 'InvalidPassword',
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# /login Test 11: User tries to log in w/ unconfirmed account
def test_login_for_unconfirmed_user(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user_unconfirmed()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    print("HTML:", html)
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
    print("CSRF Token:", csrf_token)

    # Simulate a POST request to /login
    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
    }, follow_redirects=True)
    
    # Check if redirected to the login page
    assert response.request.path == '/login'
    clear_users_table()



# ---------------------------------------------------------------------------------------------------------------
# Testing route: /register
# Summary: 
# Test 12: Happy path, scenario a (all fields, valid email, username, pw)
# Test 13: Happy path, scenario b (all required fields, valid email, username, pw)
# Test 14: User attempts to log in w/o valid CSRF token.
# Test 15: No CSP headers in page
# Test 16: Missing req. field: email address
# Test 17: Missing req. field: username
# Test 18: Missing req. field: password
# Test 19: Missing req. field: password confirmation
# Test 20: Password fails strength test (uses pw = 'a' for test) 
# Test 21: PW =! PW confirmation 
# Test 22: User enters illegitimate email address.
# Test 23: User enters prohibited char in any user inputs (using '>' as test)
# Test 24: User enters an already-registered username.
# Test 25: User enters an already-registered email address.
   
    
# /register Test 12: Happy path, scenario a (all fields, valid email, username, pw) --> user redirected to /index w/ success 
def test_register_happy_path_part_a(client):
    with app.app_context():
        global test_number
        test_number += 1
        print(f'Running test number: {test_number}')

        # Mock the email sending function
        with patch('app.mail.send') as mock_send:
            # Configure the mock to do nothing
            mock_send.return_value = None

            # Make a GET request to the register page to get the CSRF token
            response = client.get('/register')
            assert response.status_code == 200
            html = response.data.decode()
            csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
            response = client.post('/register', data={
                'csrf_token': csrf_token,
                'name_first': 'John',
                'name_last': 'Doe',
                'gender': 'male',
                'birthdate': '1901-01-01',
                'user_email': 'unregistered@mattmcdonnell.net',
                'username': 'test_username',
                'password': 'test123',
                'password_confirmation': 'test123',
            }, follow_redirects=True)

            mock_send.assert_called_once()
            assert response.request.path == '/login'
            clear_users_table()


# /register Test 13: Happy path, scenario b (all req. fields, valid email, username, pw) --> user redirected to /index w/ success 
def test_register_happy_path_part_b(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': '',
            'name_last': '',
            'gender': 'undisclosed',
            'birthdate': '',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_called_once()
        assert response.request.path == '/login'
        clear_users_table()



# /register Test 14: User attempts to log in w/o valid CSRF token.
def test_register_missing_CSRF(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None
    
        # Create test user in test DB.
        test_user = insert_test_user()

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate a POST request to /register
        response = client.post('/register', data={
            'csrf_token': 'invalid_token',
            'name_first': '',
            'name_last': '',
            'gender': 'undisclosed',
            'birthdate': '',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()


# /register Test 15: Tests for presence of CSP headers in page.
def test_register_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to a page (e.g., the login page)
        response = client.get('/register')
        assert response.status_code == 200

        # Check if CSP headers are set correctly in the response
        csp_header = response.headers.get('Content-Security-Policy')
        assert csp_header is not None
        clear_users_table()


# /register Test 16: Missing user email address.
def test_register_missing_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': ' ',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()

# /register Test 17: Missing username.
def test_register_missing_username(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': '  ',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()

# /register Test 18: Missing PW.
def test_register_missing_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': '',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()


# /register Test 19: Missing PW confirmation.
def test_register_missing_pw_confirm(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None
    
        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': '',
        }, follow_redirects=True)
    
        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()

# /register Test 20: Fails pw strength.
def test_register_pw_strength(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'a',
            'password_confirmation': 'a',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()

# /register Test 21: PW != PW confirmation.
def test_register_pw_mismatch(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test1234',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()

# /register Test 22: User enters illegitimate email address.
def test_register_bad_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregisteredmattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()


# /register Test 23: User enters prohibited chars.
def test_register_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'Joh>n',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': 'test_username',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()


# /register Test 24: User enters an already-registered username.
def test_register_duplicate_username(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')
    
    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        test_user = insert_test_user()

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': 'unregistered@mattmcdonnell.net',
            'username': test_user['username'],
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()


# /register Test 25: User enters an already-registered email address.
def test_register_duplicate_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        test_user = insert_test_user()

        # Make a GET request to the register page to get the CSRF token
        response = client.get('/register')
        assert response.status_code == 200
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        
        response = client.post('/register', data={
            'csrf_token': csrf_token,
            'name_first': 'John',
            'name_last': 'Doe',
            'gender': 'male',
            'birthdate': '1901-01-01',
            'user_email': test_user['user_email'],
            'username': 'randomuser',
            'password': 'test123',
            'password_confirmation': 'test123',
        }, follow_redirects=True)

        mock_send.assert_not_called()
        assert response.request.path == '/register'
        clear_users_table()



# ---------------------------------------------------------------------------------------------------------------
# Testing route: /profile
# Summary: 
# Test 26: Happy path (all req. fields, valid email, username, pw)
# Test 27: User attempts to log in w/o valid CSRF token.
# Test 28: Tests for presence of CSP headers in page.
# Test 29: Failed allowed chars check on user input (using > in first name)


# /profile Test 26: Happy path to updating profile (note: not all fields need be filled)
def test_profile_happy_path(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/profile')
    assert response.status_code == 200

    profile_response = client.post('/profile', data={
        'csrf_token': csrf_token,
        'name_first': 'John',
        'name_last': 'Doe',
        'username' : 'UnusedUsername',
        'gender': 'male',
        'birthdate': '1901-01-01',
    }, follow_redirects=True)

    assert profile_response.request.path == '/profile'
    clear_users_table()


# /profile Test 27: User attempts to log in w/o valid CSRF token.
def test_profile_missing_CSRF(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/profile')
    assert response.status_code == 200

    profile_response = client.post('/profile', data={
        'csrf_token': ['invalid_token'],
        'name_first': 'John',
        'name_last': 'Doe',
        'username_input' : 'UnusedUsername',
        'gender': 'male',
        'birthdate': '1901-01-01',
    }, follow_redirects=True)

    assert profile_response.request.path == '/profile'
    clear_users_table()


# /profile Test 28: Tests for presence of CSP headers in page.
def test_profile_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/profile')
    assert response.status_code == 200

    # Check if CSP headers are set correctly in the response
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None
    clear_users_table()


# /profile Test 29: Prohibited chars in user input (> in first name)
def test_profile_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/profile')
    assert response.status_code == 200

    response = client.post('/profile', data={
        'csrf_token': ['invalid_token'],
        'name_first_input': 'John>',
        'name_last_input': 'Doe',
        'gender_input': 'male',
        'birthdate_input': '1984-05-08',
        'username_input': 'test_username',
    }, follow_redirects=True)
    
    assert response.status_code == 400
    assert response.request.path == '/profile'
    clear_users_table()


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /pw_change
# Summary: 
# Test 30: Happy path (all req. fields, valid email, username, pw)
# Test 31: User attempts to log in w/o valid CSRF token.    
# Test 32: Tests for presence of CSP headers in page.
# Test 33: No user email submitted
# Test 34: No current password submitted
# Test 35: No new password submitted
# Test 36: No new password confirmation submitted
# Test 37: No prohibited chars submitted (using > in new password)
# Test 38: New password does not meet strength requirements
# Test 39: New password and new password confirmation don't match
# Test 40: User-entered email is not registered in DB
# Test 41: User entered incorrect value for current PW


# Test 30: /pw_change Happy path
def test_pw_change_happy_path(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password_old': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/'
    clear_users_table()


# Test 31: /pw_change User attempts to log in w/o valid CSRF token.
def test_pw_change_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': ['invalid_token'],
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmationed': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 32: Tests for presence of CSP headers in page.
def test_pw_change_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    # Check if CSP headers are set correctly in the response
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None


# Test 33: /pw_change No user email submitted
def test_pw_change_no_user_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': '',
        'password': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 34: /pw_change No current pw submitted
def test_pw_change_no_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': '',
        'password': 'test1234',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 35: /pw_change No new pw submitted
def test_pw_change_no_new_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': '',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 36: /pw_change No new pw confirmation submitted
def test_pw_change_no_new_pw_confirm(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmation': ''
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 37: /pw_change No prohibited chars submitted
def test_pw_change_no_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': 'test1234>*&$',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 38: /pw_change New password does not meet strength requirements
def test_pw_change_pw_strength(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': 'a',
        'password_confirmation': 'a'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 39: /pw_change New password and new password confirmation don't match
def test_pw_change_matching_pws(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmation': 'test12345'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 40: /pw_change User-entered email is not registered in DB
def test_pw_change_registered_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': 'unregistered@mattmcdonnell.net',
        'password': test_user['pw_unhashed'],
        'password': 'test1234',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# Test 41: /pw_change User entered incorrect value for current PW
def test_pw_change_correct_current_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'
    
    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_change')
    assert response.status_code == 200

    response = client.post('/pw_change', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': 'invalid_password',
        'password': 'test1234',
        'password_confirmation': 'test1234'
    }, follow_redirects=True) 
    
    assert response.request.path == '/pw_change'
    clear_users_table()


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /pw_reset_req
# Summary: 
# Test 42: Happy path (all req. fields, valid email, username, pw)
# Test 43: User attempts to log in w/o valid CSRF token.    
# Test 44: Tests for presence of CSP headers in page.
# Test 45: No user email submitted
# Test 46: Prohibited chars in user-submitted email address
# Test 47: User submits an invalid email address format.
# Test 48: User submits unregistered email address


# Test 42: /pw_reset_req Happy path
def test_pw_reset_req_happy_path(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)


    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': csrf_token,
            'user_email': test_user['user_email']
        }, follow_redirects=True)

        # Assert that the mock was called
        mock_send_mail.assert_called_once()

    assert response.request.path == '/login'
    clear_users_table()


# Test 43: /pw_reset_req User attempts to log in w/o valid CSRF token.
def test_pw_reset_req_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)


    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': 'invalid_token',
            'user_email': test_user['user_email']
        }, follow_redirects=True)

        
    assert response.request.path == '/pw_reset_req'
    clear_users_table()


# Test 44: /pw_reset_req Tests for presence of CSP headers in page.
def test_pw_reset_req_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create test user in test DB.
    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Simulate a POST request to /login
    login_response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)
    assert login_response.request.path == '/'

    # Make a GET request to a page (e.g., the login page)
    response = client.get('/pw_reset_req')
    assert response.status_code == 200

    # Check if CSP headers are set correctly in the response
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None
    clear_users_table()


# Test 45: /pw_reset_req User submitted no value for email
def test_pw_reset_req_no_email_submitted(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)


    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': csrf_token,
            'user_email': ''
        }, follow_redirects=True)

    assert response.request.path == '/pw_reset_req'
    clear_users_table()



# Test 46: /pw_reset_req User submitted prohibited chars
def test_pw_reset_req_invalid_chars(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)


    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': csrf_token,
            'user_email': 'test_em>il@mattmcdonnell.net'
        }, follow_redirects=True)

    assert response.request.path == '/pw_reset_req'
    clear_users_table()



# Test 47: /pw_reset_req User submits an invalid email address format.
def test_pw_reset_req_valid_email_format(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': csrf_token,
            'user_email': 'matt-mattmcdonnell.net'
        }, follow_redirects=True)

    assert response.request.path == '/pw_reset_req'
    clear_users_table()


# Test 48: /pw_reset_req User-entered email not in database
def test_pw_reset_req_unregistered_email(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user()

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)


    # Mock the mail.send function
    with patch('flask_mail.Mail.send') as mock_send_mail:
        # Configure the mock to do nothing
        mock_send_mail.return_value = None

        response = client.post('/pw_reset_req', data={
            'csrf_token': csrf_token,
            'user_email': 'unregistered@mattmcdonnell.net'
        }, follow_redirects=True)

    assert response.request.path == '/login'
    clear_users_table()


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /pw_reset_new
# Summary: 
# Test 49: Happy path (all req. fields, valid email, username, pw)
# Test 50: User attempts to log in w/o valid CSRF token.    
# Test 51: Tests for presence of CSP headers in page.
# Test 52: User submits invalid token via GET
# Test 53: Missing value for pw_reset_new
# Test 54: Missing value for pw_reset_new_confirm
# Test 55: Missing value for pw_reset_new and pw_reset_new_confirm    
# Test 56: User enters prohibited chars
# Test 57: User enters insufficiently strong PW
# Test 58: Mismatching pw_reset_new and pw_reset_new_confirm
# Test 59: New password matches old password



# Test 49: /pw_reset/new Happy path
def test_pw_reset_new_happy_path(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc123456',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/login'

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('login', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'user_email': test_user['user_email'],
            'password': 'abc123456'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/'
        clear_users_table()


# /pw_reset/new Test 50: User attempts to log in w/o valid CSRF token.
def test_pw_reset_new_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': 'invalid_csrf',
            'password': 'abc123456',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()



# /pw_reset/new Test 51: Tests for presence of CSP headers in page.
def test_pw_reset_new_csp_headers(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc123456',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Check if CSP headers are set correctly in the response
        csp_header = response.headers.get('Content-Security-Policy')
        assert csp_header is not None

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/login'
        clear_users_table()


# /pw_reset/new Test 52: Invalid token- user submits invalid token via GET 
def test_pw_reset_new_bad_token_get(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')
            invalid_token_url = url_for('pw_reset_new', token='invalid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(invalid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(invalid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc123456',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/login'
        clear_users_table()


# /pw_reset/new Test 53: Missing value for pw_reset_new
def test_pw_reset_new_missing_pw_reset_new(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': '',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 54: Missing value for pw_reset_new_confirm
def test_pw_reset_new_missing_pw_reset_new_confirm(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc123456',
            'password_confirmation': ''
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 55: Missing value for pw_reset_new and pw_reset_new_confirm
def test_pw_reset_new_missing_pw_reset_new_and_confirm(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': '',
            'password_confirmation': ''
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 56: User enters prohibited chars
def test_pw_reset_new_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc123>@()',
            'password_confirmation': 'abc123>@()'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 57: User enters insufficiently strong PW
def test_pw_reset_new_weak_new_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'a',
            'password_confirmation': 'a'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 58: Mismatching pw_reset_new and pw_reset_new_confirm
def test_pw_reset_new_pw_mismatch(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': 'abc12345',
            'password_confirmation': 'abc1234'
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# /pw_reset/new Test 59: New password matches old password
def test_pw_reset_new_pw_new_pw_matches_old_pw(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    # Create a new test user
    test_user = insert_test_user()

    # Mock verify_reset_token to simulate a valid token
    with patch('app.verify_reset_token') as mock_verify:
        # Mock return value to simulate a valid token (returning the test user's ID or email)
        mock_verify.return_value = {'user_id': test_user['user_id']}

        with app.test_request_context():
            # Create the URL with a 'valid' token
            valid_token_url = url_for('pw_reset_new', token='valid_token')

        # Make a GET request to the reset password page to get the CSRF token
        get_response = client.get(valid_token_url)
        assert get_response.status_code == 200
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

        # Simulate the POST request with the new password and CSRF token
        response = client.post(valid_token_url, data={
            'csrf_token': csrf_token,
            'password': test_user['pw_unhashed'],
            'password_confirmation': test_user['pw_unhashed']
        }, follow_redirects=True)

        # Verify that the response is a redirect to the home page
        assert response.request.path == '/pw_reset_new/valid_token'
        clear_users_table()


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /register_confirmation
# Summary: 
# Test 60: /register_confirmation Happy path


# Test 60: /register_confirmation Happy path
def test_register_confirmation_happy_path(client):
    global test_number
    test_number += 1
    print(f'Running test number: {test_number}')

    test_user = insert_test_user_unconfirmed()

    # Mock verify_reset_token to return the user_id of the created test user
    with patch('app.verify_reset_token') as mock_verify:
        mock_verify.return_value = {'user_id': test_user['user_id']}  # Use the test user's ID

        with app.test_request_context():
            # Create the URL with a 'valid' token
            confirmation_url = url_for('register_confirmation', token='valid_token')
        
        # Simulate the GET request
        response = client.get(confirmation_url)

        # Verify that the response is a redirect (status code 302)
        assert response.status_code == 302

        # Generate the expected redirect URL
        with app.test_request_context():
            expected_url = url_for('index', _external=False)

        # Check that the response redirects to the index page
        assert expected_url in response.location
        clear_users_table()