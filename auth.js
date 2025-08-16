// auth.js - Frontend authentication for ZapManejo dashboard
// Integrates with Mark's existing frontend and API

class ZapmanejoAuth {
  constructor() {
    this.token = localStorage.getItem('zapmanejo_token');
    this.user = JSON.parse(localStorage.getItem('zapmanejo_user') || 'null');
    this.baseURL = 'https://faas-nyc1-2ef2e6cc.doserverless.co';
    this.authPath = '/api/v1/web/fn-cf616548-9087-4219-a8d4-07173ff27fb0/possohelp/auth';
  }

  // Set authentication token
  setToken(token, user) {
    this.token = token;
    this.user = user;
    localStorage.setItem('zapmanejo_token', token);
    localStorage.setItem('zapmanejo_user', JSON.stringify(user));
  }

  // Clear authentication
  clearAuth() {
    this.token = null;
    this.user = null;
    localStorage.removeItem('zapmanejo_token');
    localStorage.removeItem('zapmanejo_user');
  }

  // Check if user is authenticated
  isAuthenticated() {
    return this.token && this.user && this.user.is_active;
  }

  // Get authorization headers
  getAuthHeaders() {
    const headers = {
      'Content-Type': 'application/json'
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  // Register new user
  async register(username, email, password, phoneNumber = '') {
    try {
      const response = await fetch(`${this.baseURL}${this.authPath}/register`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({
          username,
          email,
          password,
          phone_number: phoneNumber
        })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Registration error:', error);
      return { success: false, message: 'Network error during registration' };
    }
  }

  // Login user
  async login(email, password) {
    try {
      const response = await fetch(`${this.baseURL}${this.authPath}/login`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();
      
      if (data.success && data.token) {
        this.setToken(data.token, data.user);
      }
      
      return data;
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, message: 'Network error during login' };
    }
  }

  // Verify email with code
  async verifyEmail(email, code) {
    try {
      const response = await fetch(`${this.baseURL}${this.authPath}/verify-email`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ email, code })
      });

      const data = await response.json();
      
      if (data.success && data.token) {
        this.setToken(data.token, data.user);
      }
      
      return data;
    } catch (error) {
      console.error('Email verification error:', error);
      return { success: false, message: 'Network error during verification' };
    }
  }

  // Link phone number to account
  async linkPhoneNumber(phoneNumber) {
    try {
      const response = await fetch(`${this.baseURL}${this.authPath}/link-phone`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ phone_number: phoneNumber })
      });

      return await response.json();
    } catch (error) {
      console.error('Phone linking error:', error);
      return { success: false, message: 'Network error during phone linking' };
    }
  }

  // Get user profile
  async getUserProfile() {
    try {
      const response = await fetch(`${this.baseURL}/api/user/profile`, {
        headers: this.getAuthHeaders()
      });

      if (response.ok) {
        return await response.json();
      }
      return null;
    } catch (error) {
      console.error('Profile fetch error:', error);
      return null;
    }
  }

  // Logout user
  logout() {
    this.clearAuth();
    window.location.href = '/login.html';
  }
}

// Initialize authentication
const auth = new ZapmanejoAuth();

// Enhanced registration form handler
document.addEventListener('DOMContentLoaded', function() {
  const registerForm = document.getElementById('register-form');
  const loginForm = document.getElementById('login-form');
  const verificationForm = document.getElementById('verification-form');

  // Registration form submission
  if (registerForm) {
    registerForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const username = document.getElementById('username-input').value;
      const email = document.getElementById('email-input').value;
      const password = document.getElementById('password-input').value;
      const confirmPassword = document.getElementById('confirm-input').value;
      const phoneNumber = document.getElementById('phone-input').value || '';
      
      const errorElement = document.getElementById('error-message');
      const successElement = document.getElementById('success-message');
      
      // Clear previous messages
      errorElement.style.display = 'none';
      successElement.style.display = 'none';

      // Validate passwords match
      if (password !== confirmPassword) {
        errorElement.textContent = 'Passwords do not match';
        errorElement.style.display = 'block';
        return;
      }

      // Show loading state
      const submitBtn = document.getElementById('register-button');
      const originalText = submitBtn.textContent;
      submitBtn.textContent = 'Registering...';
      submitBtn.disabled = true;

      try {
        const result = await auth.register(username, email, password, phoneNumber);
        
        if (result.success) {
          successElement.textContent = result.message;
          successElement.style.display = 'block';
          
          // Show verification form
          document.getElementById('registration-section').style.display = 'none';
          document.getElementById('verification-section').style.display = 'block';
          document.getElementById('verification-email').textContent = email;
          
        } else {
          errorElement.textContent = result.message;
          errorElement.style.display = 'block';
        }
      } catch (error) {
        errorElement.textContent = 'Registration failed. Please try again.';
        errorElement.style.display = 'block';
      }
      
      // Reset button
      submitBtn.textContent = originalText;
      submitBtn.disabled = false;
    });
  }

  // Login form submission
  if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const email = document.getElementById('email-input').value;
      const password = document.getElementById('password-input').value;
      const errorElement = document.getElementById('error-message');
      
      errorElement.style.display = 'none';

      // Show loading state
      const submitBtn = document.getElementById('login-button');
      const originalText = submitBtn.textContent;
      submitBtn.textContent = 'Logging in...';
      submitBtn.disabled = true;

      try {
        const result = await auth.login(email, password);
        
        if (result.success) {
          window.location.href = '/index.html';
        } else {
          errorElement.textContent = result.message;
          errorElement.style.display = 'block';
        }
      } catch (error) {
        errorElement.textContent = 'Login failed. Please try again.';
        errorElement.style.display = 'block';
      }
      
      // Reset button
      submitBtn.textContent = originalText;
      submitBtn.disabled = false;
    });
  }

  // Email verification form
  if (verificationForm) {
    verificationForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const email = document.getElementById('verification-email').textContent;
      const code = document.getElementById('verification-code').value;
      const errorElement = document.getElementById('verification-error');
      
      errorElement.style.display = 'none';

      try {
        const result = await auth.verifyEmail(email, code);
        
        if (result.success) {
          window.location.href = '/index.html';
        } else {
          errorElement.textContent = result.message;
          errorElement.style.display = 'block';
        }
      } catch (error) {
        errorElement.textContent = 'Verification failed. Please try again.';
        errorElement.style.display = 'block';
      }
    });
  }

  // Check if user is authenticated on protected pages
  const currentPage = window.location.pathname;
  if (currentPage === '/index.html' || currentPage === '/' || currentPage.includes('dashboard')) {
    if (!auth.isAuthenticated()) {
      window.location.href = '/login.html';
      return;
    }
    
    // Update UI with user info
    updateDashboardUI();
  }

  // Logout functionality
  const logoutBtn = document.getElementById('logout-button');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function() {
      auth.logout();
    });
  }
});

// Update dashboard UI with user information
async function updateDashboardUI() {
  if (!auth.user) return;

  // Update profile section
  const profileName = document.querySelector('.profile .name');
  if (profileName) {
    profileName.textContent = auth.user.name || auth.user.username;
  }

  // Update phone number input if user has linked phone
  const phoneInput = document.getElementById('phone-number-input');
  if (phoneInput && auth.user.phone_number) {
    phoneInput.value = auth.user.phone_number;
    phoneInput.placeholder = auth.user.phone_number;
  }

  // Load user's ranch data
  await loadUserData();
}

// Load user-specific data
async function loadUserData() {
  if (!auth.user.phone_number) {
    showPhoneLinkingPrompt();
    return;
  }

  // Use Mark's existing Find function but with authenticated user's phone
  Find(auth.user.phone_number);
}

// Show phone linking prompt for users without linked WhatsApp
function showPhoneLinkingPrompt() {
  const linkingModal = document.createElement('div');
  linkingModal.innerHTML = `
    <div class="modal-overlay">
      <div class="modal-content">
        <h3>Link Your WhatsApp Number</h3>
        <p>To access your livestock data, please link your WhatsApp number:</p>
        <input type="text" id="link-phone-input" placeholder="+5511999999999" />
        <div class="modal-buttons">
          <button id="link-phone-btn">Link Phone</button>
          <button id="skip-linking-btn">Skip for Now</button>
        </div>
        <div id="link-error" class="error-message" style="display:none;"></div>
      </div>
    </div>
  `;
  
  document.body.appendChild(linkingModal);

  // Handle phone linking
  document.getElementById('link-phone-btn').addEventListener('click', async function() {
    const phoneNumber = document.getElementById('link-phone-input').value;
    const errorElement = document.getElementById('link-error');
    
    if (!phoneNumber) {
      errorElement.textContent = 'Please enter your WhatsApp number';
      errorElement.style.display = 'block';
      return;
    }

    try {
      const result = await auth.linkPhoneNumber(phoneNumber);
      
      if (result.success) {
        auth.user.phone_number = phoneNumber;
        localStorage.setItem('zapmanejo_user', JSON.stringify(auth.user));
        document.body.removeChild(linkingModal);
        loadUserData();
      } else {
        errorElement.textContent = result.message;
        errorElement.style.display = 'block';
      }
    } catch (error) {
      errorElement.textContent = 'Failed to link phone number';
      errorElement.style.display = 'block';
    }
  });

  // Handle skipping
  document.getElementById('skip-linking-btn').addEventListener('click', function() {
    document.body.removeChild(linkingModal);
  });
}

// Enhanced Get function that includes authentication
function GetAuthenticated(action, category, phone_number, callback) {
  let url = `/${BASE_PATH}/data/${action}/${category}/${phone_number}`;
  url = url.replace(/\/\//g, "/");

  fetch(url, {
    headers: auth.getAuthHeaders()
  })
  .then(response => {
    if (response.status === 401) {
      auth.logout();
      return;
    }
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  })
  .then(data => {
    callback(data);
  })
  .catch(error => {
    console.error('There was a problem with the fetch operation:', error);
  });
}

// Override the existing Find function to use authentication
function Find(phone_number) {
  if (!auth.isAuthenticated()) {
    window.location.href = '/login.html';
    return;
  }

  // Use authenticated requests
  GetAuthenticated("", "rain", phone_number, ChartRain);
  GetAuthenticated("", "temperature", phone_number, ChartTemperature);
  GetAuthenticated("", "births", phone_number, ChartBirths);
  GetAuthenticated("", "deaths", phone_number, ChartDeaths);
}

// Update download links to use authentication
function updateDownloadLinksWithAuth(phone_number) {
  const authParams = `?token=${encodeURIComponent(auth.token)}`;
  
  document.getElementById("download-link-births").href = 
    `${DOWNLOAD_BASE_PATH}/births/${phone_number}${authParams}`;
  document.getElementById("download-link-deaths").href = 
    `${DOWNLOAD_BASE_PATH}/deaths/${phone_number}${authParams}`;
  document.getElementById("download-link-rain").href = 
    `${DOWNLOAD_BASE_PATH}/rain/${phone_number}${authParams}`;
  document.getElementById("download-link-temperature").href = 
    `${DOWNLOAD_BASE_PATH}/temperature/${phone_number}${authParams}`;
}
