document.querySelector('.toggle-password').addEventListener('click', function () {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
});

document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    const loginButton = document.querySelector('.btn[type="submit"]');
    loginButton.disabled = true;
    loginButton.textContent = 'Logging in...';

    try {
        const response = await fetch('http://localhost:3000/api/login', { // CORRECTED ENDPOINT
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();

        if (result.success) {
            alert('Login successful!');
            
            // CRITICAL STEP: Save the JWT token received from the server
            localStorage.setItem('medlink_token', result.token); 
            
            window.location.href = 'index.html'; // Redirect to dashboard
            
        } else {
            alert(`Login failed: ${result.message}`);
        }
    } catch (error) {
        console.error('Error during login:', error);
        alert('An error occurred during login. Please try again later.');
    } finally {
        loginButton.disabled = false;
        loginButton.textContent = 'SIGN IN';
    }
});