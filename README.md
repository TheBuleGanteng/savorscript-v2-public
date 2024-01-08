# SAVORSCRIPT WEB APPLICATION SHELL W/ ENHANCED SECURITY
### Video Demo:  https://youtu.be/ikvrAdumZac

### Description:
- SavorScript is a web application template that contains all the major functionality needed in most web apps, such as database establishment, user registration, password change, password reset, and update profile. The construction has a significant focus on security and automated testing.
- This project was completed as the final project for [Harvard's CS50 2024](https://cs50.harvard.edu/x/2023/project/)
- Assignment was submitted on: 06-Jan-2024


#### Motivation for project:
Allow developers to focus on the core of their development projects, with minimal time spent re-creating common elements in web applications.


#### Key elements:
1. This project is meant to utilize elements common for most web applications, including: 
    - Sqlite3 database creation
    - User profile creation, incl. registration confirmation by email token
    - User input validation, incl. customizable password strength
    - Password reset (via email) and password change
    - User profile management by user

1. Languages used:
    - Front-end: HTML / JavaScript (using Bootstrap 5 w/ minor CSS customizations) / Jinja / Flask-WTF
    - Back-end: Python / Flask / Flask-WTF
    - Datbase: sqlite3 (managed directly with assistance of CS50 library)
    - Environment: Uses custom virtual environment (set via: source /home/thebuleganteng/TheBuleGanteng/71803511/CS50/CS50-env/bin/activate)

1. Significant focus on security:
    - All SQL inputs are parameterized to protect against SQL injection attacks
    - Use of jinja to pass user-inputted elements to HTML to protect against HTML injection attacks
    - All user input is checked against whitelisted chars to protect against SQL, HTML, XSS, and other attacks
    - Escaping of all user-generated data before being displayed in HTML 
    - Use of customized Content Security Policy (CSP) managed by Flask Talisman to protect against cross-site scripting (XSS), clickjacking and other code injection attacks
    - Use of CSRFProtect to protect against cross-site registry attacks
    - Use of cryptographic tokens sent to the user via email as part of 2-step registration and password reset processes
    - Exclusion of sensitive data (e.g. passwords from) being stored in Session or in cryptographic token used for password reset
    - Externalization of sensitive data (e.g. login needed to send emails programmatically) to .env file
    - Exclusion of .env file and other sensitive data from upload to GitHub via .gitignore file
    - Daily (12pm GST) automated purging of stale, unconfirmed user accounts via a cron job



#### KEY FEATURES:
2. Use of database to store user data
    - See: savorscript.sqlite

2. User creation/registration
    - See: app.py --> /register and register.html
    - User input is validated before submission
    - Username availability and satisfaction of password requirements is communicated to the user real-time via JavaScript
    - Registration button only appears after user has provided valid inputs to all required fields.
    - Successful validation and submission of registration form via Flask-WTF classes using custom validators and filters:
        -The user's data is entered into the database, with the user's confirmed status = False
        -The app then automatically generates a cryptographic token and sends that token to the email address provided by the user
        - The user must then click on the link the email sent to them by the application to be directed back to the application, at which time their account's status is changed to 'confirmed' in the database, allowing for login and access to the application.

2. Extensive user input validation and password management
    - See: app.py, register.html
    - Application uses standard and custom Flask-WTF filters and validators, with helpful error messages displayed to the user alongside the form fields that failed validation
    - Application uses enforces password strength custom password fully customizable parameters for password strength (min password length, min letters, min chars, min symbols, prohibited symbols)
    
2. Use of JavaScript to provide validation feedback to users, make input fields appear/disappear, and enable/disable submit button
    - See: app.py --> /profile, /register
    - See: profile.html, register.html
    - Clicking button makes input fields appear/disappear based on onclick() listener
    - Inputting data triggers real-time feedback to user about username availability and password validation
    - Inputting of all required data makes enabled submit button appear (done via promise chain).

2. Account management for existing users
    - See: app.py --> /register, /pw_change, pw_reset_req, /pw_reset_new/<token>
    - Password change (for users already logged in)
    - Password reset via cryptographic token + email link (for users not logged in)

2. Preserves flash messages and CSRF token stored in Session, even in routes where Session is cleared to enforce user to be logged out (e.g. /password reset, /register)
    - See app.py --> /register (creation of messages) and /login (display 
    of messages)
    - Stores Session data to be preserved in a temporary variable before Session is cleared, allowing that data to be used later in the route

2. Connection to gmail for programmatic email generation (including 
password reset emails)
    - See app.py --> /pw_reset_req

2. Use of CronJob to automatically remove users who have not confirmed their registration and whose token has expired

2. Use of url_for throughout
    - See: various app.py (all redirects) and htmls (all <a> links)
    - Makes links more maintainable, enables Blueprints

2. Navbar contents are dynamic based on whether user is logged in
    - See: layout.html
    - Uses jinja to alter display of navbar elements relative to whether user
    is already logged in

2. Extensive user profile management for users logged in
    - See app.py --> /profile
    - See profile.html
    - Ability for logged-in user to update their username, first and last name, 
    birthdate, gender, etc.
    
2. Use of a cool favicon :-0