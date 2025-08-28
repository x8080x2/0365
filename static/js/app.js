// Simple utility functions only - main logic is in index.html
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function getPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    if (strength < 2) return { score: 1, text: 'Weak', class: 'text-danger' };
    if (strength < 4) return { score: 2, text: 'Medium', class: 'text-warning' };
    return { score: 3, text: 'Strong', class: 'text-success' };
}

console.log('Utility functions loaded');