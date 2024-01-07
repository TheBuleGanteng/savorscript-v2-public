document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM content loaded in savorscript.js.');
    console.log('this is a console.log from savorscript.js....savorscript.js loaded successfully');

    // Global CSRF Token Variable (You should set it in your layout.html)
    let csrfToken = ''; 
    let csrfTokenInput = document.querySelector('input[name="csrf_token"]');
    if (csrfTokenInput) {
        csrfToken = csrfTokenInput.value;
        console.log("CSRF Token set:", csrfToken);
    } else {
        console.log("CSRF token input not found.");
    }


    // Make the functions globally accessible
    
    // profile
    window.jsShowHiddenInputName = jsShowHiddenInputName;
    window.jsShowHiddenInputUsername = jsShowHiddenInputUsername; 
    window.jsShowHiddenInputGender = jsShowHiddenInputGender;
    window.jsShowHiddenInputBirthdate = jsShowHiddenInputBirthdate;
    window.jsEnableProfileSubmitButton = jsEnableProfileSubmitButton;
    // register
    window.jsUsernameValidation = jsUsernameValidation;
    window.jsEmailAvailabilityCheck = jsEmailAvailabilityCheck;
    window.jsPwVal = jsPwVal;
    window.jsPwConVal = jsPwConVal;
    window.jsEnableRegisterSubmitButton = jsEnableRegisterSubmitButton;
    // pw_change
    window.jsEnablePwChangeSubmitButton = jsEnablePwChangeSubmitButton;
    // pw_reset_new
    window.jsEnablePwResetNewSubmitButton = jsEnablePwResetNewSubmitButton;
    // pw_reset_req
    window.jsEnablePwResetReqSubmitButton = jsEnablePwResetReqSubmitButton;

    
    // JS for /profile --------------------------------------------------------------
    if (window.location.href.includes('/profile')) {
        console.log("Running savorscript.js for /profile... ");

        var updateButtonName = document.getElementById('updateButtonName');
        var name_first_input = document.getElementById('name_first_input');
        var name_last_input = document.getElementById('name_last_input');
        var updateButtonUsername = document.getElementById('updateButtonUsername');
        var username = document.getElementById('username');
        var updateButtonGender = document.getElementById('updateButtonGender');
        var gender_input = document.getElementById('gender_input');
        var updateButtonBirthdate = document.getElementById('updateButtonBirthdate');
        var birthdate_input = document.getElementById('birthdate_input');



        if (updateButtonName) {
            updateButtonName.addEventListener('click', function(event) {
                event.preventDefault(); // Prevent the default anchor action
                jsShowHiddenInputName(); // Call the function
            });
        }

        if (name_first_input) {
            document.getElementById('name_first_input').addEventListener('input', function() {
                jsEnableProfileSubmitButton();
            });
        }

        if (name_last_input) {
            document.getElementById('name_last_input').addEventListener('input', function() {
                jsEnableProfileSubmitButton();
            });
        }

        if (updateButtonUsername) {
            updateButtonUsername.addEventListener('click', function(event) {
                event.preventDefault(); // Prevent the default anchor action
                jsShowHiddenInputUsername(); // Call the function
            });
        }

        if (username) {
            document.getElementById('username').addEventListener('input', function() {
                jsProfileUsernameValidation(); 
                jsEnableProfileSubmitButton();
            });
        }

        if (updateButtonGender) {
            updateButtonGender.addEventListener('click', function(event) {
                event.preventDefault(); // Prevent the default anchor action
                jsShowHiddenInputGender(); // Call the function
            });
        }

        if (gender_input) {
            document.getElementById('gender_input').addEventListener('input', function() {
                jsEnableProfileSubmitButton();
            });
        }

        if (updateButtonBirthdate) {
            updateButtonBirthdate.addEventListener('click', function(event) {
                event.preventDefault(); // Prevent the default anchor action
                jsShowHiddenInputBirthdate(); // Call the function
            });
        }

        if (birthdate_input) {
            document.getElementById('birthdate_input').addEventListener('input', function() {
                jsEnableProfileSubmitButton();
            });
        }
    } 
    // /JS for /profile --------------------------------------------------------------

    
    // JS for /pw_change.html -----------------------------------------------------------
    if (window.location.href.includes('/pw_change')) {
        console.log("Running savorscript.js for /pw_change... ");

        var user_email = document.getElementById('user_email');
        var password_old = document.getElementById('password_old');
        var password = document.getElementById('password');
        var password_confirmation = document.getElementById('password_confirmation');
        
        if (user_email) {
            document.getElementById('user_email').addEventListener('input', function() {
                jsEnablePwChangeSubmitButton();
            });
        }
        if (password_old) {
            document.getElementById('password_old').addEventListener('input', function() {
                jsEnablePwChangeSubmitButton();
            });
        }
        if (password) {
            document.getElementById('password').addEventListener('input', function() {
                jsPwVal();
                jsEnablePwChangeSubmitButton();
            });
        }
        if (password_confirmation) {
            document.getElementById('password_confirmation').addEventListener('input', function() {
                jsPwConVal();
                jsEnablePwChangeSubmitButton();
            });
        }
    } 
    // /JS for /pw_change.html -----------------------------------------------------------


    // JS for /pw_reset_new.html -----------------------------------------------------------
    if (window.location.href.includes('/pw_reset_new')) {
        console.log("Running savorscript.js for /pw_reset_new... ");

        var password = document.getElementById('password');
        var password_confirmation = document.getElementById('password_confirmation');

        if (password) {
            document.getElementById('password').addEventListener('input', function() {
                jsPwVal();
                jsEnablePwResetNewSubmitButton();
            });
        }
        if (password_confirmation) {
            document.getElementById('password_confirmation').addEventListener('input', function() {
                jsPwConVal();
                jsEnablePwResetNewSubmitButton();
            });
        }
    } 


    // JS for /pw_reset_req.html -----------------------------------------------------------
    if (window.location.href.includes('/pw_reset_req')) {
        console.log("Running savorscript.js for /pw_reset_req... ");

        var user_email = document.getElementById('user_email');
        

        if (user_email) {
            document.getElementById('user_email').addEventListener('input', function() {
                jsEnablePwResetReqSubmitButton();
            });
        }
    }


    



    // JS for /register.html -----------------------------------------------------------
    if (window.location.href.includes('/register')) {
        console.log("Running savorscript.js for /register... ");
    
        var username = document.getElementById('username');
        var user_email = document.getElementById('user_email');
        var password = document.getElementById('password');
        var password_confirmation = document.getElementById('password_confirmation');
        
        if (username) {
            console.log("In /register... Username input event triggered");
            document.getElementById('username').addEventListener('input', function() {
                jsUsernameValidation();
                jsEnableRegisterSubmitButton();
            });
        }    
        if (user_email) {
            console.log("In /register... user_email event triggered");
            document.getElementById('user_email').addEventListener('input', function() {
                jsEmailAvailabilityCheck();
                jsEnableRegisterSubmitButton();
            });
        }
        if (password) {
            console.log("In /register, password event triggered");
            document.getElementById('password').addEventListener('input', function() {
                jsPwVal();
                jsEnableRegisterSubmitButton();
            });
        }
        if (password_confirmation) {
            console.log("In /register, password_confirmation event triggered");
            document.getElementById('password_confirmation').addEventListener('input', function() {
                jsPwConVal();
                jsEnableRegisterSubmitButton();
            });
        }
    }
    // /JS for /register.html -----------------------------------------------------------


    
    // Function description: When box is clicked, input boxes for fist and last name appear.
    function jsShowHiddenInputName() {
        /* Pull in the relevant elements from the html */
        var container = document.getElementById('profile_hidden_name_container');
        var inputField1 = document.getElementById('name_first_input');
        var inputField2 = document.getElementById('name_last_input');
        var updateButton = document.getElementById('updateButtonName');
        console.log(`Running jsShowHiddenInputName()`)
        console.log(`Running jsShowHiddenInputName()...`)
        console.log(`Running jsShowHiddenInputName()... CSRF Token is ${csrfToken}`);

        
        /* Check if hidden content is already displayed */
        if (container.style.display === 'block') {
            // Hide the container and clear the input field
            container.style.display = 'none';
            inputField1.value = '';
            inputField2.value = '';
            updateButton.innerHTML = 'update';
            updateButton.color = 'grey';
            updateButton.classList.remove('btn-secondary');
            updateButton.classList.add('btn-primary');
        } else {
            // Show the container
            container.style.display = 'block';
            updateButton.innerHTML = 'undo';
            updateButton.classList.remove('btn-primary');
            updateButton.classList.add('btn-secondary');
        }
    }


    // Function description: When box is clicked, input box for username appears.
    function jsShowHiddenInputUsername() {
        /* Pull in the relevant elements from the html */
        var container = document.getElementById('profile_hidden_username');
        var inputField = document.getElementById('username');
        var updateButton = document.getElementById('updateButtonUsername');
        console.log(`Running jsShowHiddenInputUsername()`)
        console.log(`Running jsShowHiddenInputUsername()...`)
        console.log(`Running jsShowHiddenInputUsername()... CSRF Token is ${csrfToken}`);

        /* Check if hidden content is already displayed */
        if (container.style.display === 'flex') {
            // Hide the container and clear the input field
            container.style.display = 'none';
            inputField.value = '';
            updateButton.innerHTML = 'update';
            updateButton.color = 'grey';
            updateButton.classList.remove('btn-secondary');
            updateButton.classList.add('btn-primary');
        } else {
            // Show the container
            container.style.display = 'flex';
            updateButton.innerHTML = 'undo';
            updateButton.classList.remove('btn-primary');
            updateButton.classList.add('btn-secondary');
        }
    }


    // Function description: Provides real-time user feedback re availability of 
    // username + hides submit button if username is taken (username must be unique).
    // Function description: Provides real-time user feedback re availability of 
    // username + hides submit button if username is taken (username must be unique).
    function jsProfileUsernameValidation() {
        return new Promise((resolve, reject) => {
            var username = document.getElementById('username').value.trim();
            var username_validation = document.getElementById('username_validation');
            console.log(`Running jsProfileUsernameValidation()`)
            console.log(`Running jsProfileUsernameValidation()... username is: ${username}`)
            console.log(`running jsProfileUsernameValidation()... CSRF Token is: ${csrfToken}`); 

            // Username input is empty, hide the validation message and submit button
            if (username === '') {
                console.log(`Running jsUsernameValidation()... username ==='' (username is empty)`)
                username_validation.innerHTML = '';
                username_validation.style.display = 'none';
                submit_enabled = false;
                resolve(submit_enabled);
    
            // If username != empty, do the following...
            } else {
                console.log(`Running jsUsernameValidation()... username != '' (username is not not empty)`)
                fetch('/check_username_availability', {
                    method: 'POST',
                    body: new URLSearchParams({ 'username': username }),
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': csrfToken,
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    if (!response.headers.get("content-type").includes("application/json")) {
                        throw new TypeError("Response not JSON");
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.available == 'available') {
                        username_validation.innerHTML = 'Username available';
                        username_validation.style.color = '#22bd39';
                        submit_enabled = true;
                    } else {
                        username_validation.innerHTML = 'Username unavailable';
                        username_validation.style.color = 'red';
                        submit_enabled = true;
                    }
                    username_validation.style.display = 'block';
                    resolve(submit_enabled);
                })
                .catch(error => {
                    // Handle any errors here
                    console.error('Error:', error);
                    username_validation.innerHTML = 'Username available';
                    username_validation.style.color = '#22bd39';
                    username_validation.style.display = 'block';
                });
            }
        });
    }
    
    

    // Function description: When box is clicked, input box for gender appears.
    function jsShowHiddenInputGender() {
        /* Pull in the relevant elements from the html */
        var container = document.getElementById('profile_hidden_gender');
        var inputField = document.getElementById('gender_input');
        var updateButton = document.getElementById('updateButtonGender');
        console.log(`Running jsShowHiddenInputGender()`)
        console.log(`Running jsShowHiddenInputGender()...`)
        console.log(`Running jsShowHiddenInputGender()... CSRF Token is ${csrfToken}`);
        
        /* Check if hidden content is already displayed */
        if (container.style.display === 'flex') {
            // Hide the container and clear the input field
            container.style.display = 'none';
            inputField.value = '';
            updateButton.innerHTML = 'update';
            updateButton.color = 'grey';
            updateButton.classList.remove('btn-secondary');
            updateButton.classList.add('btn-primary');
            jsEnableProfileSubmitButton();
        } else {
            // Show the container
            container.style.display = 'flex';
            updateButton.innerHTML = 'undo';
            updateButton.classList.remove('btn-primary');
            updateButton.classList.add('btn-secondary');
        }
    }



    // Function description: When box is clicked, input box for birthdate appears.
    function jsShowHiddenInputBirthdate() {
        /* Pull in the relevant elements from the html */
        var container = document.getElementById('profile_hidden_birthdate');
        var inputField = document.getElementById('birthdate_input');
        var updateButton = document.getElementById('updateButtonBirthdate');
        console.log(`Running jsShowHiddenInputBirthdate()...`)
        console.log(`Running jsShowHiddenInputBirthdate()... CSRF Token is ${csrfToken}`);

        /* Check if hidden content is already displayed */
        if (container.style.display === 'flex') {
            // Hide the container and clear the input field
            container.style.display = 'none';
            inputField.value = '';
            updateButton.innerHTML = 'update';
            updateButton.color = 'grey';
            updateButton.classList.remove('btn-secondary');
            updateButton.classList.add('btn-primary');
            jsEnableProfileSubmitButton();
        } else {
            // Show the container
            container.style.display = 'flex';
            updateButton.innerHTML = 'undo';
            updateButton.classList.remove('btn-primary');
            updateButton.classList.add('btn-secondary');
        }
    }


    // Function description: Enables and shows submit button provided the user has
    // updated any of the input fields.
    async function jsEnableProfileSubmitButton() {
        
        var name_first_input = document.getElementById('name_first_input').value.trim();
        var name_last_input = document.getElementById('name_last_input').value.trim();
        var username = document.getElementById('username').value.trim();
        var birthdate_input = document.getElementById('birthdate_input').value;
        var gender_input = document.getElementById('gender_input').value;
        var username_validation_element = document.getElementById('username_validation');
        //var username_validation = username_validation_element.innerText || username_validation_element.textContent;
        //var submitButton = document.getElementById('submit_button');
        
        if (username !== '') {
            await jsProfileUsernameValidation();
        }

        var username_validation = username_validation_element.innerText || username_validation_element.textContent;
        var submitButton = document.getElementById('submit_button');
        console.log(`Running jsEnableProfileSubmitButton()...`)
        console.log(`Running jsEnableProfileSubmitButton()... value for username_validation is: ${ username_validation}`)
        console.log(`Running jsEnableProfileSubmitButton()... CSRF Token is ${csrfToken}`);


        console.log("Input Values:", {
            name_first_input,
            name_last_input,
            username,
            birthdate_input,
            gender_input,
            username_validation,
        });

        if (
            (name_first_input !== '' || name_last_input !== '' || username !== '' || birthdate_input !== '' || gender_input !== '') &&
            username_validation !== 'Username unavailable'
        ) {
            submitButton.disabled = false;
        } else {
            submitButton.disabled = true;
        }
    }
            


    

    // Declaring global variable used to enable submit button.
    // Starts off as false and if any subsequent validation (email address, username, 
    // password, etc), fail, the variable is changed to false, thus inhibiting the submit button.
    var submit_enabled = true;


    // Function description: Provides real-time user feedback re availability of 
    // username + hides submit button if username is taken (username must be unique).
    // Function description: Provides real-time user feedback re availability of 
    // username + hides submit button if username is taken (username must be unique).

    function jsUsernameValidation() {
        return new Promise((resolve, reject) => {
            var username = document.getElementById('username').value.trim();
            var username_validation = document.getElementById('username_validation');
            console.log(`Running jsUsernameValidation()`)    
            console.log(`Running jsUsernameValidation()... username is: ${username}`)
            console.log(`running jsUsernameValidation()... CSRF Token is: ${csrfToken}`); 

            // Username input is empty, hide the validation message and submit button
            if (username === '') {
                console.log(`Running jsUsernameValidation()... username==='' (username is empty)`)
                username_validation.innerHTML = '';
                username_validation.style.display = 'none';
                submit_enabled = false;
                resolve(submit_enabled);
    
            // If username != empty, do the following...
            } else {
                console.log(`Running jsUsernameValidation()... username != '' (username is not not empty)`)
                fetch('/check_username_availability', {
                    method: 'POST',
                    body: new URLSearchParams({ 'username': username }),
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': csrfToken,
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    if (!response.headers.get("content-type").includes("application/json")) {
                        throw new TypeError("Response not JSON");
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.available == 'available') {
                        username_validation.innerHTML = 'Username available';
                        username_validation.style.color = '#22bd39';
                        submit_enabled = true;
                    } else {
                        username_validation.innerHTML = 'Username unavailable';
                        username_validation.style.color = 'red';
                        submit_enabled = true;
                    }
                    username_validation.style.display = 'block';
                    resolve(submit_enabled);
                })
                .catch(error => {
                    // Handle any errors here
                    console.error('Error:', error);
                    username_validation.innerHTML = 'Username available';
                    username_validation.style.color = '#22bd39';
                    username_validation.style.display = 'block';
                });
            }
        });
    }
    

    // Function description: Provides real-time user feedback re whether user-entered
    // email address is already registered + hides submit button if user-entered email address
    // is already registered (user email must be unique).
    function jsEmailAvailabilityCheck() {
        return new Promise((resolve, reject) => {
            var user_email = document.getElementById('user_email').value.trim();
            var user_email_validation = document.getElementById('user_email_validation');
            console.log(`Running jsEmailAvailabilityCheck()`)
            console.log(`running jsEmailAvailabilityCheck()... user_email is ${user_email}`)
            console.log(`running jsEmailAvailabilityCheck()... CSRF Token is: ${csrfToken}`);         

            if (user_email === '') {
                // Email input is empty, hide the validation message
                user_email_validation.innerHTML = '';
                user_email_validation.style.display = 'none';
                submit_enabled = false;
                resolve(submit_enabled);
            } else {
                // Email input is not empty, perform a real-time check
                fetch('/check_email_availability', {
                    method: 'POST',
                    body: new URLSearchParams({ 'user_email': user_email }),
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRFToken': csrfToken,
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    if (!response.headers.get("content-type").includes("application/json")) {
                        throw new TypeError("Response not JSON");
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.email_check_result == 'invalid_format') {
                        // Email is of an invalid format --> display error message and disable submit.
                        user_email_validation.innerHTML = 'Please enter a valid email address.';
                        user_email_validation.style.color = 'red';
                        submit_enabled = false;
                    } else if (data.email_check_result == 'already_registered') {
                        // Email is already registered --> display error message and disable submit.
                        user_email_validation.innerHTML = 'Email address already registered. Please login or reset your password.';
                        user_email_validation.style.color = 'red';
                        submit_enabled = false;
                    } else if (data.email_check_result == 'available') {
                        // Email is valid format + not already registered --> display success message.
                        user_email_validation.innerHTML = 'Email address not registered';
                        user_email_validation.style.color = '#22bd39';
                        submit_enabled = true;
                    }
                    user_email_validation.style.display = 'block';
                    resolve(submit_enabled);
                })
                .catch(error => {
                    // Handle any errors here
                    console.error('Error:', error);
                    user_email_validation.innerHTML = 'Email available';
                    user_email_validation.style.color = '#22bd39';
                    user_email_validation.style.display = 'block';
                });
            }
        });
    }


    // Function description: Provides real-time user feedback re whether their input meets PW 
    /// requirements.
    function jsPwVal() {
        return new Promise((resolve, reject) => {
            var password = document.getElementById('password').value.trim();
            var password_confirmation = document.getElementById('password_confirmation').value.trim();
            var regLiMinTotChars = document.getElementById('pw_min_tot_chars_li');
            var regLiMinLetters = document.getElementById('pw_min_letters_li');
            var regLiMinNum = document.getElementById('pw_min_num_li');
            var regLiMinSym = document.getElementById('pw_min_sym_li');
            var regLiMatch = document.getElementById('pw_match_c');
            console.log(`Running jsPwVal()`)
            console.log(`running jsPwVal()... CSRF Token is: ${csrfToken}`);
            
            // Helper function: resets color of element to black
            function resetColor(elements) {
                if (!Array.isArray(elements)) {
                    elements = [elements]; // Wrap the single element in an array
                }
                elements.forEach(element => {
                    element.style.color = 'black';
                });
            }

            // Helper function: set color of element to #22bd39 (success green)
            function setColor(elements) {
                if (!Array.isArray(elements)) {
                    elements = [elements]; // Wrap the single element in an array
                }
                elements.forEach(element => {
                    element.style.color = '#22bd39';
                });
            }
            
            // If password is blank, reset the color of the elements below and return false.
            if (password === '') {
                resetColor([regLiMinTotChars, regLiMinLetters, regLiMinNum, regLiMinSym, regLiMatch]);
                return resolve(false);
            }
            // If password is not blank, then toss the value over to the /check_password_strength in app.py
            fetch('/check_password_strength', {
                method: 'POST',
                body: new URLSearchParams({ 
                    'password': password,
                    'password_confirmation': password_confirmation
                }),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken,
                }
            })
            // Do the following with the result received back from app.py
            .then(response => response.json())
            .then(data => {
                let submit_enabled = true;
                if (data.checks_passed.includes('pw_reg_length')) {
                    setColor(regLiMinTotChars);
                } else {
                    resetColor(regLiMinTotChars);
                    submit_enabled = false;
                }

                if (data.checks_passed.includes('pw_req_letter')) {
                    setColor(regLiMinLetters);
                } else {
                    resetColor(regLiMinLetters);
                    submit_enabled = false;
                }

                if (data.checks_passed.includes('pw_req_num')) {
                    setColor(regLiMinNum);
                } else {
                    resetColor(regLiMinNum);
                    submit_enabled = false;
                }

                if (data.checks_passed.includes('pw_req_symbol')) {
                    setColor(regLiMinSym);
                } else {
                    resetColor(regLiMinSym);
                    submit_enabled = false;
                }

                if (data.confirmation_match) {
                    setColor(regLiMatch);
                } else {
                    resetColor(regLiMatch);
                    submit_enabled = false;
                }

                resolve(submit_enabled);
            })
            .catch(error => {
                console.error('Error: password checking in registration has hit an error.', error);
                reject(error);
            });
        });
    }


    // Function description: Provides real-time user feedback re whether their input meets 
    // PW Confirmation requirements.
    function jsPwConVal() {
        return new Promise((resolve, reject) => {
            var password = document.getElementById('password').value.trim();
            var password_confirmation = document.getElementById('password_confirmation').value.trim();
            var regLiMinTotChars = document.getElementById('pw_min_tot_chars_li_c');
            var regLiMinLetters = document.getElementById('pw_min_letters_li_c');
            var regLiMinNum = document.getElementById('pw_min_num_li_c');
            var regLiMinSym = document.getElementById('pw_min_sym_li_c');
            var regLiMatch = document.getElementById('pw_match_c');
            console.log(`Running jsPwConVal()`)
            console.log(`running jsPwConVal()... CSRF Token is: ${csrfToken}`);
            
            // Helper function: resets color of element to black
            function resetColor(elements) {
                if (!Array.isArray(elements)) {
                    elements = [elements]; // Wrap the single element in an array
                }
                elements.forEach(element => {
                    element.style.color = 'black';
                });
            }

            // Helper function: set color of element to #22bd39 (success green)
            function setColor(elements) {
                if (!Array.isArray(elements)) {
                    elements = [elements]; // Wrap the single element in an array
                }
                elements.forEach(element => {
                    element.style.color = '#22bd39';
                });
            }
            // If password_confirmation is blank, reset the color of the elements below and return false.
            if (password_confirmation === '') {
                resetColor([regLiMinTotChars, regLiMinLetters, regLiMinNum, regLiMinSym, regLiMatch]);
                return resolve(false);
            }
            // If submit_confirmation is not blank, then toss the value over to the /check_password_strength in app.py
            fetch('/check_password_strength', {
                method: 'POST',
                body: new URLSearchParams({ 
                    'password': password,
                    'password_confirmation': password_confirmation
                }),
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': csrfToken,
                }
            })
            // Do the following with the result received back from app.py
            .then(response => response.json())
            .then(data => {
                let submit_enabled = true;
                if (data.checks_passed_confirmation.includes('pw_reg_length')) {
                    setColor(regLiMinTotChars);
                } else {
                    resetColor(regLiMinTotChars);
                    submit_enabled = false;
                }

                if (data.checks_passed_confirmation.includes('pw_req_letter')) {
                    setColor(regLiMinLetters);
                } else {
                    resetColor(regLiMinLetters);
                    submit_enabled = false;
                }

                if (data.checks_passed_confirmation.includes('pw_req_num')) {
                    setColor(regLiMinNum);
                } else {
                    resetColor(regLiMinNum);
                    submit_enabled = false;
                }

                if (data.checks_passed_confirmation.includes('pw_req_symbol')) {
                    setColor(regLiMinSym);
                } else {
                    resetColor(regLiMinSym);
                    submit_enabled = false;
                }

                if (data.confirmation_match) {
                    setColor(regLiMatch);
                } else {
                    resetColor(regLiMatch);
                    submit_enabled = false;
                }

                resolve(submit_enabled);
            })
            .catch(error => {
                console.error('Error: password_confirmation checking in registration has hit an error.', error);
                reject(error);
            });
        });
    }

    // Function description: Enables and shows submit button provided the user has
    // completed all of the required input fields.
    async function jsEnableRegisterSubmitButton() {
        var submitButton = document.getElementById('submit_button');
        var username = document.getElementById('username').value.trim();
        var username_validation_element = document.getElementById('username_validation');
        if (username !== '') {
            await jsProfileUsernameValidation();
        }
        var username_validation = username_validation_element.innerText || username_validation_element.textContent;
    
        // Create an array of promises with labels
        var labeledPromises = [
            { label: 'Username Validation', promise: jsUsernameValidation() },
            { label: 'Email Validation', promise: jsEmailAvailabilityCheck() },
            { label: 'Password Check', promise: jsPwVal() },
            { label: 'Password Confirmation Check', promise: jsPwConVal() }
        ];
        console.log(`Running jsEnableRegisterSubmitButton()`)
        console.log(`Running jsEnableRegisterSubmitButton()... CSRF Token is: ${csrfToken}`);
    
        Promise.all(labeledPromises.map(labeledPromise => {
            // Add a console.log statement before each promise
            console.log(`Running jsEnableRegisterSubmitButton()... Executing promise: ${labeledPromise.label}`);
    
            return labeledPromise.promise.then(result => {
                // Add a console.log statement after each promise resolves
                console.log(`Running jsEnableRegisterSubmitButton()... Promise (${labeledPromise.label}) resolved with result: ${result}`);
                return { label: labeledPromise.label, result: result };
            });
        }))
            .then((results) => {
                // Log each promise result
                results.forEach(res => {
                    console.log(`Result of ${res.label}: ${res.result}`);
                });
    
                // Check if any of the promises return false
                var allPromisesPassed = results.every(res => res.result === true);
                
                if (!allPromisesPassed || username_validation === 'Username unavailable') {
                    submitButton.disabled = true;
                    console.log(`Running jsEnableRegisterSubmitButton()... Submit button disabled.`);
                } else {
                    // All validations passed
                    console.log(`Running jsEnableRegisterSubmitButton()... All validation checks passed, enabling submit button.`);
                    submitButton.disabled = false;
                }
            }).catch((error) => {
                // Handle errors if any of the Promises reject
                console.error(`Running jsEnableRegisterSubmitButton()... Error is: ${error}.`);
                submitButton.disabled = true;
            });
    }


    // pw_ch functions --------------------------------------------------------------------
    


    // Function description: Enables and shows submit button provided the user has
    // updated any of the input fields.
    function jsEnablePwChangeSubmitButton() {
        
        var user_email = document.getElementById('user_email').value.trim();
        var password_old = document.getElementById('password_old').value.trim();
        var password = document.getElementById('password').value.trim();
        var password_confirmation = document.getElementById('password_confirmation').value.trim();
        var submitButton = document.getElementById('submit_button');
        console.log(`Running jsEnablePwChangeSubmitButton()...`)
        console.log(`Running jsEnablePwChangeSubmitButton()... CSRF Token is ${csrfToken}`);

        console.log("Running jsEnablePwChangeSubmitButton... input values are:", {
            'user_email' : user_email,
        });

        // Logic for checking conditions
        var pwValPromise = jsPwVal(password); // Assuming jsPwVal returns a Promise
        var pwConValPromise = jsPwConVal(password_confirmation); // Assuming jsPwConVal returns a Promise

        Promise.all([pwValPromise, pwConValPromise]).then(function (results) {
            var pwValResult = results[0]; // Result of jsPwVal
            var pwConValResult = results[1]; // Result of jsPwConVal
            console.log(`running jsEnablePwChangeSubmitButton... pwValResult is: ${ pwValResult }.`)
            console.log(`running jsEnablePwChangeSubmitButton... pwConValResult is: ${ pwConValResult }.`)

            if (
                user_email !== '' &&
                password_old !== '' &&
                password !== '' &&
                password_confirmation !== '' &&
                pwValResult === true &&
                pwConValResult === true
            ) {
                console.log(`running jsEnablePwChangeSubmitButton... submit button enabled.`)
                submitButton.disabled = false;
            } else {
                console.log(`running jsEnablePwChangeSubmitButton... submit button disabled.`)
                submitButton.disabled = true;
            }
        });
    }
    // /pw_ch functions -------------------------------------------------------------------



    // pw_reset_new functions --------------------------------------------------------------------

    // Function description: Enables and shows submit button provided the user has
    // updated any of the input fields.
    function jsEnablePwResetNewSubmitButton() {
        
        var password = document.getElementById('password').value.trim();
        var password_confirmation = document.getElementById('password_confirmation').value.trim();
        var submitButton = document.getElementById('submit_button');
        console.log(`Running jsEnablePwResetNewSubmitButton()...`)
        console.log(`Running jsEnablePwResetNewSubmitButton()... CSRF Token is ${csrfToken}`);


        // Logic for checking conditions
        var pwValPromise = jsPwVal(password); // Assuming jsPwVal returns a Promise
        var pwConValPromise = jsPwConVal(password_confirmation); // Assuming jsPwConVal returns a Promise

        Promise.all([pwValPromise, pwConValPromise]).then(function (results) {
            var pwValResult = results[0]; // Result of jsPwVal
            var pwConValResult = results[1]; // Result of jsPwConVal
            console.log(`running jsEnablePwResetNewSubmitButton... pwValResult is: ${ pwValResult }.`)
            console.log(`running jsEnablePwResetNewSubmitButton... pwConValResult is: ${ pwConValResult }.`)

            if (
                password !== '' &&
                password_confirmation !== '' &&
                pwValResult === true &&
                pwConValResult === true
            ) {
                console.log(`running jsEnablePwResetNewSubmitButton... submit button enabled.`)
                submitButton.disabled = false;
            } else {
                console.log(`running jsEnablePwResetNewSubmitButton... submit button disabled.`)
                submitButton.disabled = true;
            }
        });
    }

    // /pw_reset_new functions --------------------------------------------------------------------



    // pw_reset_req functions --------------------------------------------------------------------
    function jsEnablePwResetReqSubmitButton() {
        
        var user_email = document.getElementById('user_email').value.trim();
        var submitButton = document.getElementById('submit_button');
        console.log(`Running jsEnablePwResetReqSubmitButton()...`)
        console.log(`Running jsEnablePwResetReqSubmitButton()... CSRF Token is ${csrfToken}`);

        if (
            user_email !== ''
        ) {
            console.log(`running jsEnablePwResetReqSubmitButton... submit button enabled.`)
            submitButton.disabled = false;
        } else {
            console.log(`running jsEnablePwResetReqSubmitButton... submit button disabled.`)
            submitButton.disabled = true;
        }
    };

    // /pw_reset_req functions --------------------------------------------------------------------




});