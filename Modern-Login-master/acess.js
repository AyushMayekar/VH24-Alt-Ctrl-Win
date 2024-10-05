
document.getElementById('A').addEventListener('click', function() {
    document.getElementById('popup').style.display = 'flex';
});

document.getElementById('closePopup').addEventListener('click', function() {
    document.getElementById('popup').style.display = 'none';
});


document.getElementById('U').addEventListener('click', function() {
    window.location.href = "#"; 
});

document.getElementById('L').addEventListener('click', function() {
    window.location.href = "index.html";
});



const popup = document.getElementById('popup');
const submitButton = document.getElementById('submitPassword');

submitButton.addEventListener('click', async (event) => {
    event.preventDefault(); 
    const adminpassword = document.getElementById('adminPassword').value;
    const adminemail = document.getElementById('adminemail').value;

    const formData = new URLSearchParams();
    formData.append('adminemail', adminemail);
    formData.append('adminpassword', adminpassword);

    try {
        const response = await fetch('http://127.0.0.1:8000/admin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: formData.toString(),
        });
        const data = await response.json();

        if (response.ok) {
            alert('Admin access granted!!');
            localStorage.setItem('access_token', data.access_token);
            window.location.href = 'admin.html'; // admin dashboard
        } else {
            alert(`Error: ${data.detail}`);
        }
    } catch (error) {
        console.error('An error occurred:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
});

