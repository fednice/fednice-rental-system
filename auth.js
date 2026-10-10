// === FEDNICE Secure Auth System - Remembers Landlords ===

// Hash password securely
async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// REGISTER NEW LANDLORD
async function registerLandlord(username, password, phone) {
  if(!username || !password) {
    alert('Please fill all fields!');
    return;
  }
  
  const hashed = await hashPassword(password);
  const landlords = JSON.parse(localStorage.getItem('fednice_landlords') || '[]');
  
  if(landlords.find(l => l.username === username)) {
    alert('Username already exists! Try another one.');
    return;
  }

  landlords.push({ 
    username, 
    password: hashed, 
    phone, 
    createdAt: new Date().toISOString() 
  });
  
  localStorage.setItem('fednice_landlords', JSON.stringify(landlords));
  alert('Account created! Now you can login anytime you come back.');
  window.location.href = 'login.html';
}

// LOGIN - Remembers landlord
async function loginLandlord(username, password, rememberMe) {
  const hashed = await hashPassword(password);
  const landlords = JSON.parse(localStorage.getItem('fednice_landlords') || '[]');
  const found = landlords.find(l => l.username === username && l.password === hashed);

  if(found) {
    const session = { username, loginTime: new Date().toISOString() };
    
    if(rememberMe) {
      localStorage.setItem('fednice_session', JSON.stringify(session));
    } else {
      sessionStorage.setItem('fednice_session', JSON.stringify(session));
    }
    localStorage.setItem('fednice_current_user', username);
    
    alert('Welcome back ' + username + '!');
    window.location.href = 'dashboard.html';
  } else {
    alert('Wrong username or password!');
  }
}

// AUTO LOGIN CHECK - Run on page load
function checkAutoLogin() {
  const session = localStorage.getItem('fednice_session') || sessionStorage.getItem('fednice_session');
  if(session) {
    const user = JSON.parse(session);
    const currentPage = window.location.pathname;
    // If on login page and already logged in, go to dashboard
    if(currentPage.includes('login.html') || currentPage.includes('signup.html')) {
      window.location.href = 'dashboard.html';
    }
    return user.username;
  }
  return null;
}

// LOGOUT
function logout() {
  localStorage.removeItem('fednice_session');
  sessionStorage.removeItem('fednice_session');
  localStorage.removeItem('fednice_current_user');
  window.location.href = 'login.html';
}

// Attach buttons automatically
document.addEventListener('DOMContentLoaded', () => {
  checkAutoLogin();
  
  const signupBtn = document.getElementById('signupBtn');
  if(signupBtn) {
    signupBtn.onclick = async () => {
      const u = document.getElementById('username').value;
      const p = document.getElementById('password').value;
      const ph = document.getElementById('phone') ? document.getElementById('phone').value : '';
      await registerLandlord(u, p, ph);
    };
  }

  const loginBtn = document.getElementById('loginBtn');
  if(loginBtn) {
    loginBtn.onclick = async () => {
      const u = document.getElementById('username').value;
      const p = document.getElementById('password').value;
      const r = document.getElementById('rememberMe') ? document.getElementById('rememberMe').checked : true;
      await loginLandlord(u, p, r);
    };
  }
});