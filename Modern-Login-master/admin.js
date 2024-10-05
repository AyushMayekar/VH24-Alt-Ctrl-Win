
const email = "admin@example.com";  
const tokenIssuedAt = 1696411200;   
const currentLoggedInUsers = 5;     

document.getElementById('user-email').textContent = email;

function formatLoginTime(unixTimestamp) {
    const date = new Date(unixTimestamp * 1000);
    return date.toLocaleString();
}

const loginTimeFormatted = formatLoginTime(tokenIssuedAt);
document.getElementById('login-time').textContent = loginTimeFormatted;

document.getElementById('logged-users').textContent = currentLoggedInUsers;
