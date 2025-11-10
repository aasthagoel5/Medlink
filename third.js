// --- Initial Setup and Event Listeners ---
const otpInputs = document.querySelectorAll('.code-inputs input[type="text"]'); // Corrected selector
const resendLink = document.querySelector('.resend a');

// CRITICAL: Get the userId saved from the registration page
const userId = sessionStorage.getItem('medlink_userId'); 

// Ensure inputs are collected into a single form element
const verificationContainer = document.querySelector('.verification-container'); 
const confirmBtn = document.getElementById('confirmBtn');

if (!userId) {
    alert('User ID not found. Please register again.');
    confirmBtn.disabled = true;
    // Optionally redirect back to signup page
}

otpInputs.forEach((input, index) => {
    // ... existing input logic (moving focus) ...
    input.addEventListener('input', () => {
        if (input.value.length > 1) {
            input.value = input.value.slice(0, 1);
        }
        if (index < otpInputs.length - 1 && input.value) {
            otpInputs[index + 1].focus();
        } else if (input.value && index === otpInputs.length - 1) {
            confirmBtn.focus(); // Focus on button when last digit entered
        }
    });
});

// --- Timer/Countdown Logic ---
// Note: You need a <span id="timer"></span> element in your HTML for this to work
let countdownInterval;
const otpValidityDuration = 300; // 5 minutes (300 seconds) - Matches server

function startCountdown(duration) {
    let timeRemaining = duration;
    resendLink.disabled = true;
    // Removed timerDisplay references as the element isn't in your HTML
    countdownInterval = setInterval(() => {
        timeRemaining--;
        if (timeRemaining <= 0) {
            clearInterval(countdownInterval);
            resendLink.disabled = false;
        }
    }, 1000);
}
startCountdown(otpValidityDuration);


// --- CONFIRM OTP Verification Logic ---
confirmBtn.addEventListener('click', async (e) => {
    e.preventDefault();

    if (!userId) {
        alert('User session expired. Please register again.');
        window.location.href = 'create account.html';
        return;
    }
    
    // Collect the 4-digit OTP
    const otpValue = Array.from(otpInputs).map(input => input.value).join('');
    
    if (otpValue.length !== otpInputs.length) {
        alert('Please enter the complete 4-digit OTP.');
        return;
    }

    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Verifying...';

    try {
        const response = await fetch('http://localhost:3000/api/verify-otp', { // CORRECTED ENDPOINT
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ otp: otpValue, userId: userId }) // Pass retrieved userId
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('OTP verified successfully! You are now logged in.');
            clearInterval(countdownInterval);
            
            // CRITICAL STEP: Save the JWT token received from the server
            localStorage.setItem('medlink_token', result.token); 
            sessionStorage.removeItem('medlink_userId'); // Clean up user ID from session
            
            window.location.href = 'index.html'; // Redirect to dashboard
            
        } else {
            alert(`Verification failed: ${result.message}`);
        }
    } catch (error) {
        console.error('Error verifying OTP:', error);
        alert('An error occurred while verifying the OTP. Please try again later.');
    } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Confirm';
    }
});


// --- RESEND OTP Logic ---
resendLink.addEventListener('click', async (e) => {
    e.preventDefault();
    if(resendLink.disabled) return;
    
    if (!userId) {
        alert('User session expired. Cannot resend.');
        return;
    }

    resendLink.disabled = true;

    try {
        const response = await fetch('http://localhost:3000/api/resend-otp', { // CORRECTED ENDPOINT
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: userId }) // Pass retrieved userId
        });
        
        const result = await response.json();
        
        if (result.success) {
            alert('OTP resent successfully!');
            startCountdown(otpValidityDuration);
        } else {
            alert('Failed to resend OTP. Please try again.');
        }
    } catch (error) {
        console.error('Error resending OTP:', error);
        alert('An error occurred while resending the OTP. Please try again later.');
    } finally {
        // Will be re-enabled by the countdown
    }
});