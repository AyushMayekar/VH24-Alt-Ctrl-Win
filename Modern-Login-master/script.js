const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('loginform');
const showLoginBtn = document.getElementById('showLogin'); // Button to show login form
const showSignUpBtn = document.getElementById('showSignUp');

// Existing logic for the toggle buttons

showSignUpBtn.addEventListener('click', () => {
    container.classList.add("active");
});

showLoginBtn.addEventListener('click', () => {
    container.classList.remove("active");
});


registerBtn.addEventListener('submit', async (event) => {
    event.preventDefault(); 
    const email = document.getElementById('emailsingup').value;
    const password = document.getElementById('passwordsignup').value;
    const Confirmpassword = document.getElementById('Confirmpasswordsignup').value;

    if (!email || !password || !Confirmpassword) {
        alert('Please enter email, password and Confirm password.');
        return;
    }

    if (password !== Confirmpassword) {
        alert('Passwords do not match.');
        return;
    }

    const payload = {
        email: email,
        password: password,
        confirm_password: Confirmpassword
    };

    console.log(payload);
    try {
        const response = await fetch('http://127.0.0.1:8000/register/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });
        const data = await response.json();

        if (response.ok) {
            alert('Sign In successful!');
            localStorage.setItem('access_token', data.access_token);
            window.location.href = 'index.html';
        } else {
            alert(`Error: ${data.detail}`);
        }
    } catch (error) {
        console.error('An error occurred:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
});


loginBtn.addEventListener('submit', async (event) => {
    event.preventDefault(); 
    const email = document.getElementById('emaillogin').value;
    const password = document.getElementById('passwordlogin').value;

    if (!email || !password) {
        alert('Please enter both email and password.');
        return;
    }
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    try {
        const response = await fetch('http://127.0.0.1:8000/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString(),
        });
        const data = await response.json();

        if (response.ok) {
            alert('Login successful!');
            localStorage.setItem('access_token', data.access_token);
            window.location.href = 'acess.html';
        } else {
            alert(`Error: ${data.detail}`);
        }
    } catch (error) {
        console.error('An error occurred:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
});


document.querySelector("body").addEventListener("mousemove", eyeball);

function eyeball(event) { 
    'use strict';
    var eye = document.querySelectorAll(".eye");
    eye.forEach(function (eye) {
        let x = (eye.getBoundingClientRect().left) + (eye.clientWidth / 2);
        let y = (eye.getBoundingClientRect().top) + (eye.clientHeight / 2);
        let radian = Math.atan2(event.pageX - x, event.pageY - y);
        let rot = (radian * (180 / Math.PI) * -1) + 270;
        eye.style.transform = "rotate(" + rot + "deg)";
    });
}


