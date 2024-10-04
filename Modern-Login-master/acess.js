
document.getElementById('A').addEventListener('click', function() {
    document.getElementById('popup').style.display = 'flex';
});

document.getElementById('closePopup').addEventListener('click', function() {
    document.getElementById('popup').style.display = 'none';
});

document.getElementById('submitPassword').addEventListener('click', function() {
    const password = document.getElementById('adminPassword').value;

    if (password !== null && password !== "") {
        window.location.href = "admin.html"; 
    } else {
        alert('Password cannot be empty!');
    }
});

document.getElementById('U').addEventListener('click', function() {
    window.location.href = "#"; 
});

document.getElementById('L').addEventListener('click', function() {
    window.location.href = "index.html";
});
