from app import create_app, db as test_db
from models import User
from configs.testing_config import TestingConfig
from datetime import date, datetime
from flask import url_for, Flask
from helpers import get_reset_token, verify_reset_token
import os
import pytest
import re
from flask_sqlalchemy import SQLAlchemy
import shutil
from sqlalchemy import inspect
from unittest.mock import patch, MagicMock
from urllib.parse import unquote
import urllib.parse
import uuid
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True, scope="function")
def setup_test_database():
    app = create_app('testing')
    with app.app_context():
        test_db.create_all()
        yield app
        test_db.drop_all()

@pytest.fixture(scope="function")
def client(app):
    with app.test_client() as test_client:
        yield test_client

# Setup steps summary: 
# Setup step 1: Creates a timestamp that can be added to print statements to aid debugging
# Setup step 2: Defines function to create a test user in the DB where confirmed = 1.
# Setup step 3: Defines function to delete the test test user
# Setup step 4: Defines function to create an UNCONFIRMED test user in the DB where confirmed = 0
# Setup step 5: Defines function to delete the unconfirmed test user
# Setup step 6: Create an instance of app.py for testing.
# Setup step 7: Defines function to clear the users table
# Setup step 8: Declare global variable for test number

# Setup step 1: Creates a timestamp that can be added to print statements to aid debugging
execution_order_counter = 0
def get_execution_order():
    global execution_order_counter
    execution_order_counter += 1
    return execution_order_counter


#Setup step 2: Defines function to create a test user in the DB where confirmed = 1
def insert_test_user(test_app):
    with test_app.app_context():
        test_user_email = f'{uuid.uuid4()}@mattmcdonnell.net'
        test_password_unhashed = 'GLBMjKJ3qphUodwvqyF!+-='
        test_password_hashed = generate_password_hash(test_password_unhashed)
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
        test_db.session.add(test_user)
        try:
            test_db.session.commit()
        except Exception as e:
            print(f'{get_execution_order()} -- running insert_test_user(app)... error during commit is: { e }')
            return None
        user_data_test_user = User.query.filter_by(user_email=test_user_email).first()
        if user_data_test_user:
            user_data_test_user = user_data_test_user.as_dict()
            user_data_test_user['pw_unhashed'] = test_password_unhashed
            print(f'{get_execution_order()} -- running insert_test_user(app)... user_data_test_user is: { user_data_test_user }')
            return user_data_test_user
        else:
            print(f'{get_execution_order()} -- running insert_test_user(app)... no user_data_test_user created')
            return None



# Setup step 3: Defines function to delete the test test user
def delete_test_user(user_email,test_app):
    with test_app.app_context():
        user_data_test_user = User.query.filter_by(user_email=user_email).first()
        if user_data_test_user:
            print(f'{get_execution_order()} -- running delete_test_user(user_email, app)... user_data_test_user is: { user_data_test_user }')
            test_db.session.delete(user_data_test_user)
            test_db.session.commit()
            print(f'{get_execution_order()} -- running delete_test_user(user_email, app)... user_data_test_user deleted from session')
        else:
            print(f'{get_execution_order()} -- running delete_test_user(user_email)... no user_data_test_user found in DB.')

        

# Setup step 4: Defines function to create an UNCONFIRMED test user in the DB where confirmed = 0
def insert_test_user_unconfirmed(test_app):
    with test_app.app_context():
        test_user_email = f'{uuid.uuid4()}@mattmcdonnell.net'
        test_password_unhashed = 'GLBMjKJ3qphUodwvqyF!+-='
        test_password_hashed = generate_password_hash(test_password_unhashed)
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
        test_db.session.add(test_user)
        try:
            test_db.session.commit()
        except Exception as e:
            print(f'{get_execution_order()} -- running insert_test_user_unconfirmed(app)... error during commit is: { e }')
            return None
        user_data_unconfirmed_user = User.query.filter_by(user_email=test_user_email).first()
        if user_data_unconfirmed_user:
            user_data_unconfirmed_user = user_data_unconfirmed_user.as_dict()
            user_data_unconfirmed_user['pw_unhashed'] = test_password_unhashed
            print(f'{get_execution_order()} -- running insert_test_user_unconfirmed(app)... user_data_unconfirmed_user is: { user_data_unconfirmed_user }')
            return user_data_unconfirmed_user
        else:
            print(f'{get_execution_order()} -- running insert_test_user_unconfirmed(app)... no user_data_unconfirmed_user created')
            return None


# Setup step 5: Defines function to delete the unconfirmed test user
def delete_test_user_unconfirmed(user_email, test_app):
    with test_app.app_context():
        user_data_unconfirmed_user = User.query.filter_by(user_email=user_email).first()
        if user_data_unconfirmed_user:
            print(f'{get_execution_order()} -- running delete_test_user_unconfirmed(user_email, app)... user_data_unconfirmed_user is: { user_data_unconfirmed_user }')
            test_db.session.delete(user_data_unconfirmed_user)
            test_db.session.commit()
            print(f'{get_execution_order()} -- running delete_test_user_unconfirmed(user_email, app)... user_data_unconfirmed_user deleted from session')
        else:
            print(f'{get_execution_order()} -- running delete_test_user_unconfirmed(user_email)... no user_data_unconfirmed_user found in DB.')


# Setup step 6: Create an instance of app.py for testing.
@pytest.fixture(scope="function")
def client():
    app = create_app('testing')  # Create the test app
    with app.test_client() as test_client:
        yield test_client


# Setup step 7: Define function to clear the users table
def clear_users_table(test_app):
    with test_app.app_context():
        User.query.delete()
        test_db.session.commit()



# Setup step 8: Declare global variable for test number
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


# /login Test 1: Happy Path: user logs in w/ valid  email address + valid password --> user redirected to / w/ success message.
def test_login_happy_path(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

    response = client.get('/login')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    response = client.post('/login', data={
        'csrf_token': csrf_token,
        'user_email': test_user['user_email'],
        'password': test_user['pw_unhashed']
    }, follow_redirects=True)

    assert response.request.path == '/'
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')
    


# /login Test 2: User attempts to log in w/o valid CSRF token.
def test_login_missing_CSRF(client):
    #db = setup_test_database()
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /login Test 3: Tests for presence of CSP headers in page.
def test_login_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

    # Make a GET request to the login page to get the CSRF token
    response = client.get('/login')
    assert response.status_code == 200

    # Check if CSP headers are set correctly in the response
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /login Test 4: User does not submit email address
def test_login_without_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 5: User does not submit PW
def test_login_without_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 6: User does not submit username or password  --> is redirected 
# to /login and flashed message.
def test_login_without_email_without_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /login Test 7: User enters undeliverable email address.
def test_login_undeliverable_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return
    
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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 8: User tries to log in w/ unregistered email address + correct PW
def test_login_with_unregistered_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 9: User tries to log in w/ registered email address + invalid PW
def test_login_with_invalid_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 10: User tries to log in w/ unregistered email address + invalid PW
def test_login_with_invalid_username_invalid_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



# /login Test 11: User tries to log in w/ unconfirmed account
def test_login_for_unconfirmed_user(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user
    test_user = insert_test_user_unconfirmed(client.application)
    if not test_user:
        print(f'{get_execution_order()} -- running test number: { test_number }... failed to generate test_user')
        return

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



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
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        # Make a GET request to the register page to get the CSRF token
        print(f'{get_execution_order()} -- running test number: { test_number }... url_map is: { client.application.url_map }')
        print(f'{get_execution_order()} -- running test number: { test_number }... app config is: { client.application.config }')
        
        response = client.get('/register')
        if response.status_code != 200:
            print(f'{get_execution_order()} -- running test number: { test_number }... response.status_code is: { response.status_code }')
            print(f'{get_execution_order()} -- running test number: { test_number }... response body is: { response.data.decode() }')
            
        assert response.status_code == 200, f'{get_execution_order()} -- running test number: { test_number }... Failed to load /register. Check route availability in test setup.'
        
        
        html = response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)
        print(f'{get_execution_order()} -- running test number: { test_number }... csrf_token is: { csrf_token }')

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
        print(f'{get_execution_order()} -- running test number: { test_number }... response is: { response }')

        mock_send.assert_called_once()
        assert response.request.path == '/login'
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 13: Happy path, scenario b (all req. fields, valid email, username, pw) --> user redirected to /index w/ success 
def test_register_happy_path_part_b(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 14: User attempts to log in w/o valid CSRF token.
def test_register_missing_CSRF(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None
    
        # Create test user in test DB.
        test_user = insert_test_user(client.application)

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 15: Tests for presence of CSP headers in page.
def test_register_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 16: Missing user email address.
def test_register_missing_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 17: Missing username.
def test_register_missing_username(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 18: Missing PW.
def test_register_missing_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 19: Missing PW confirmation.
def test_register_missing_pw_confirm(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 20: Fails pw strength.
def test_register_pw_strength(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 21: PW != PW confirmation.
def test_register_pw_mismatch(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 22: User enters illegitimate email address.
def test_register_bad_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 23: User enters prohibited chars.
def test_register_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 24: User enters an already-registered username.
def test_register_duplicate_username(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')
    
    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        test_user = insert_test_user(client.application)

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /register Test 25: User enters an already-registered email address.
def test_register_duplicate_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Mock the email sending function
    with patch('app.mail.send') as mock_send:
        # Configure the mock to do nothing
        mock_send.return_value = None

        test_user = insert_test_user(client.application)

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')



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
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /profile Test 27: User attempts to log in w/o valid CSRF token.
def test_profile_missing_CSRF(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /profile Test 28: Tests for presence of CSP headers in page.
def test_profile_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /profile Test 29: Prohibited chars in user input (> in first name)
def test_profile_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


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
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 31: /pw_change User attempts to log in w/o valid CSRF token.
def test_pw_change_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 32: Tests for presence of CSP headers in page.
def test_pw_change_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 34: /pw_change No current pw submitted
def test_pw_change_no_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 35: /pw_change No new pw submitted
def test_pw_change_no_new_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 36: /pw_change No new pw confirmation submitted
def test_pw_change_no_new_pw_confirm(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 37: /pw_change No prohibited chars submitted
def test_pw_change_no_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 38: /pw_change New password does not meet strength requirements
def test_pw_change_pw_strength(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 39: /pw_change New password and new password confirmation don't match
def test_pw_change_matching_pws(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 40: /pw_change User-entered email is not registered in DB
def test_pw_change_registered_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 41: /pw_change User entered incorrect value for current PW
def test_pw_change_correct_current_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


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
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 43: /pw_reset_req User attempts to log in w/o valid CSRF token.
def test_pw_reset_req_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 44: /pw_reset_req Tests for presence of CSP headers in page.
def test_pw_reset_req_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create test user in test DB.
    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 45: /pw_reset_req User submitted no value for email
def test_pw_reset_req_no_email_submitted(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 46: /pw_reset_req User submitted prohibited chars
def test_pw_reset_req_invalid_chars(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 47: /pw_reset_req User submits an invalid email address format.
def test_pw_reset_req_valid_email_format(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# Test 48: /pw_reset_req User-entered email not in database
def test_pw_reset_req_unregistered_email(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user(client.application)

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
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


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
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    
    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)

    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': 'test_password123',  # Using the original unhashed password as new password
        'password_confirmation': 'test_password123'
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/login'
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 50: User attempts to log in w/o valid CSRF token.
def test_pw_reset_new_missing_csrf(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)

    # Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])

    # Verify the token
    with patch('helpers.verify_reset_token', return_value={'user_id': test_user['user_id']}) as mock_verify:
        with client.application.test_request_context():
            # Create the URL with the real token
            valid_token_url = url_for('pw_reset_new', token=real_token)

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
        decoded_token_url = unquote(valid_token_url)
        assert response.request.path == decoded_token_url
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /pw_reset/new Test 51: Tests for presence of CSP headers in page.
def test_pw_reset_new_csp_headers(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)

    # Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])

    # Verify the token
    with patch('helpers.verify_reset_token', return_value={'user_id': test_user['user_id']}) as mock_verify:
        with client.application.test_request_context():
            # Create the URL with the real token
            valid_token_url = url_for('pw_reset_new', token=real_token)

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
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /pw_reset/new Test 52: Invalid token- user submits invalid token via GET 
def test_pw_reset_new_bad_token_get(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)

    # Use an invalid token for the test
    with client.application.test_request_context():
        invalid_token_url = url_for('pw_reset_new', token='invalid_token')

    # Mock verify_reset_token to return None for an invalid token
    with patch('helpers.verify_reset_token', return_value=None):
        # Make a GET request to the reset password page with the invalid token
        get_response = client.get(invalid_token_url)
        assert get_response.status_code == 302  # Update this as per your application's behavior for invalid token

        # Extract CSRF token if your page still renders a form in case of invalid token
        html = get_response.data.decode()
        csrf_token = re.search('name="csrf_token" type="hidden" value="(.+?)"', html)
        csrf_token = csrf_token.group(1) if csrf_token else None

        # Simulate the POST request with the new password and CSRF token
        response = client.post(invalid_token_url, data={
            'csrf_token': csrf_token if csrf_token else 'dummy_csrf',
            'password': 'abc123456',
            'password_confirmation': 'abc123456'
        }, follow_redirects=True)

        # Verify the response for invalid token scenario
        # This should be modified according to how your application handles invalid token cases
        assert response.request.path != '/login'  # Expecting not to be redirected to login for invalid token

    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test completed')


# /pw_reset/new Test 53: Missing value for pw_reset_new
def test_pw_reset_new_missing_pw_reset_new(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': '',  # Using the original unhashed password as new password
        'password_confirmation': 'test_password123'
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 54: Missing value for pw_reset_new_confirm
def test_pw_reset_new_missing_pw_reset_new_confirm(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': 'test_password123',
        'password_confirmation': ''
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 55: Missing value for pw_reset_new and pw_reset_new_confirm
def test_pw_reset_new_missing_pw_reset_new_and_confirm(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': '',
        'password_confirmation': ''
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 56: User enters prohibited chars
def test_pw_reset_new_prohibited_chars(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': 'test_passwor><d123',
        'password_confirmation': 'test_passwor><d123'
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 57: User enters insufficiently strong PW
def test_pw_reset_new_weak_new_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')

    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': 'a',
        'password_confirmation': 'a'
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 58: Mismatching pw_reset_new and pw_reset_new_confirm
def test_pw_reset_new_missing_pw_new_and_pw_new_confirm(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': 'abc12345',
        'password_confirmation': 'abc123456'
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# /pw_reset/new Test 59: New password matches old password
def test_pw_reset_new_pw_new_pw_matches_old_pw(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    # Create a new test user
    test_user = insert_test_user(client.application)
    print(f'{get_execution_order()} -- running test number: { test_number }... test_user is: { test_user }')

    # Step 1: Get the CSRF token from the password reset request page
    response = client.get('/pw_reset_req')
    assert response.status_code == 200
    html = response.data.decode()
    csrf_token_req = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 2: User provided valid email address to /pw_reset_req
    response = client.post('/pw_reset_req', data={
        'csrf_token': csrf_token_req,
        'user_email': test_user['user_email']
    }, follow_redirects=True)
    assert response.status_code == 200  # or other appropriate status code

    # Step 3: Generate a real token for the test user
    real_token = get_reset_token(test_user['user_id'])    
    print(f'{get_execution_order()} -- running test number: { test_number }... real_token is: { real_token }')

    # Step 4: User access pw_reset_new with a valid token
    with client.application.test_request_context():
        reset_url = url_for('pw_reset_new', token=real_token)
        print(f'{get_execution_order()} -- running test number: { test_number }... reset_url is: { reset_url }')


    # Step 5: Get the CSRF token from the reset pag    
    get_response = client.get(reset_url)
    assert get_response.status_code == 200
    html = get_response.data.decode()
    csrf_token_reset = re.search('name="csrf_token" type="hidden" value="(.+?)"', html).group(1)

    # Step 6: Submit the new password and confirmation    
    response = client.post(reset_url, data={
        'csrf_token': csrf_token_reset,
        'password': test_user['pw_unhashed'],
        'password_confirmation': test_user['pw_unhashed']
    }, follow_redirects=True)

    # Verify the response redirects to the login page
    assert response.request.path == '/pw_reset_new/'+real_token
    clear_users_table(client.application)
    print(f'{get_execution_order()} -- running test number: {test_number}... test completed')


# ---------------------------------------------------------------------------------------------------------------
# Testing route: /register_confirmation
# Summary: 
# Test 60: /register_confirmation Happy path


# Test 60: /register_confirmation Happy path
def test_register_confirmation_happy_path(client):
    global test_number
    test_number += 1
    print(f'{get_execution_order()} -- running test number: { test_number }... test started')

    test_user = insert_test_user_unconfirmed(client.application)

    # Mock verify_reset_token to return the user_id of the created test user
    with patch('app.verify_reset_token') as mock_verify:
        mock_verify.return_value = {'user_id': test_user['user_id']}  # Use the test user's ID

        with client.application.test_request_context():
            # Create the URL with a 'valid' token
            confirmation_url = url_for('register_confirmation', token='valid_token')
        
        # Simulate the GET request
        response = client.get(confirmation_url)

        # Verify that the response is a redirect (status code 302)
        assert response.status_code == 302

        # Generate the expected redirect URL
        with client.application.test_request_context():
            expected_url = url_for('index', _external=False)

        # Check that the response redirects to the index page
        assert expected_url in response.location
        clear_users_table(client.application)
        print(f'{get_execution_order()} -- running test number: { test_number }... test completed')