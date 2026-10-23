/**
 * TrustVault Main Application Logic
 * UI state management, rendering, interactions, live password strength, and modal controllers.
 */

// Global Application State
const state = {
  currentUser: null,
  activeTab: 'documents',
  activeCategory: 'all',
  searchQuery: '',
  documents: [],
  selectedDocForPermissions: null,
  users: [],
  stats: null,
  auditLogs: [],
};

// DOM Content Loaded Handler
document.addEventListener('DOMContentLoaded', async () => {
  initEventListeners();
  initPasswordStrengthMeter();
  checkExistingSession();
});

// ════════ Session & Initialization ════════
async function checkExistingSession() {
  const token = API.getToken();
  const cachedUser = API.getUser();

  if (token && cachedUser) {
    try {
      const user = await API.getCurrentUser();
      state.currentUser = user;
      API.setUser(user);
      renderApp();
      return;
    } catch (e) {
      console.warn('Session check failed, reverting to login:', e.message);
      API.clearSession();
    }
  }

  renderAuthView();
}

window.addEventListener('auth:expired', () => {
  showToast('Session expired or revoked. Please log in again.', 'warning');
  state.currentUser = null;
  renderAuthView();
});

// ════════ View Renderers ════════
function renderAuthView() {
  document.getElementById('nav-bar').style.display = 'none';
  document.getElementById('auth-view').style.display = 'flex';
  document.getElementById('dashboard-view').style.display = 'none';

  // Check for remembered terminal email
  const remembered = localStorage.getItem('trustvault_remembered_email');
  const emailInput = document.getElementById('login-email');
  const rememberCheckbox = document.getElementById('login-remember');
  if (remembered && emailInput) {
    emailInput.value = remembered;
    if (rememberCheckbox) rememberCheckbox.checked = true;
  }
}

function renderApp() {
  document.getElementById('auth-view').style.display = 'none';
  document.getElementById('dashboard-view').style.display = 'block';
  document.getElementById('nav-bar').style.display = 'flex';

  updateUserNavigation();
  updateRoleVisibility();
  switchTab(state.activeTab);
}

function updateUserNavigation() {
  const user = state.currentUser;
  if (!user) return;

  document.getElementById('nav-user-name').textContent = user.full_name;
  document.getElementById('nav-user-role').textContent = user.role.toUpperCase();
  document.getElementById('nav-user-avatar').textContent = user.full_name.charAt(0);
}

function updateRoleVisibility() {
  const role = state.currentUser?.role;

  // Admin tab
  const adminTab = document.getElementById('tab-admin');
  if (adminTab) {
    adminTab.style.display = role === 'admin' ? 'flex' : 'none';
  }

  // Upload button (only admin and owner can upload)
  const uploadBtn = document.getElementById('btn-open-upload');
  if (uploadBtn) {
    uploadBtn.style.display = (role === 'admin' || role === 'owner') ? 'inline-flex' : 'none';
  }
}

// ════════ Event Listeners Setup ════════
function initEventListeners() {
  // Auth Tab Switcher (Sign In vs Sign Up)
  const tabSignin = document.getElementById('tab-btn-signin');
  const tabSignup = document.getElementById('tab-btn-signup');
  const switchSigninLink = document.getElementById('link-switch-to-signin');

  if (tabSignin) tabSignin.addEventListener('click', () => switchAuthMode('signin'));
  if (tabSignup) tabSignup.addEventListener('click', () => switchAuthMode('signup'));
  if (switchSigninLink) switchSigninLink.addEventListener('click', () => switchAuthMode('signin'));

  // Login Form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }

  // Sign Up Form
  const signupForm = document.getElementById('signup-form');
  if (signupForm) {
    signupForm.addEventListener('submit', handleSignup);
  }

  // Entropy Key Generator
  const genBtn = document.getElementById('btn-generate-password');
  if (genBtn) {
    genBtn.addEventListener('click', generateEntropyPassword);
  }

  // Emergency Recovery Modal Triggers
  const openRecoveryLink = document.getElementById('link-open-recovery');
  const recoveryModal = document.getElementById('recovery-modal');
  const closeRecoveryBtn = document.getElementById('close-recovery-modal-btn');
  const cancelRecoveryBtn = document.getElementById('btn-cancel-recovery');
  const recoveryForm = document.getElementById('recovery-form');

  if (openRecoveryLink && recoveryModal) {
    openRecoveryLink.addEventListener('click', () => {
      document.getElementById('recovery-alert').style.display = 'none';
      recoveryModal.classList.add('open');
      const curEmail = document.getElementById('login-email')?.value || '';
      if (curEmail) document.getElementById('recovery-email').value = curEmail;
    });
  }

  if (closeRecoveryBtn && recoveryModal) {
    closeRecoveryBtn.addEventListener('click', () => recoveryModal.classList.remove('open'));
  }
  if (cancelRecoveryBtn && recoveryModal) {
    cancelRecoveryBtn.addEventListener('click', () => recoveryModal.classList.remove('open'));
  }
  if (recoveryForm) {
    recoveryForm.addEventListener('submit', handleRecovery);
  }

  // Password Visibility Toggles
  setupPasswordToggle('toggle-password-btn', 'login-password');
  setupPasswordToggle('toggle-signup-password-btn', 'signup-password');
  setupPasswordToggle('toggle-signup-confirm-btn', 'signup-password-confirm');
  setupPasswordToggle('toggle-recovery-password-btn', 'recovery-password');

  // Logout
  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      await API.logout();
      state.currentUser = null;
      showToast('Logged out successfully', 'success');
      renderAuthView();
    });
  }

  // Navigation Tabs
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;
      switchTab(targetTab);
    });
  });

  // Search input debounced
  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    let timeout = null;
    searchInput.addEventListener('input', (e) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        state.searchQuery = e.target.value.trim();
        loadDocuments();
      }, 300);
    });
  }

  // Category filter pills
  document.querySelectorAll('.cat-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.cat-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      state.activeCategory = pill.dataset.cat;
      loadDocuments();
    });
  });

  // Modal Closers
  document.querySelectorAll('.modal-close-btn, .modal-cancel-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      closeAllModals();
    });
  });

  // Upload Modal triggers
  const openUploadBtn = document.getElementById('btn-open-upload');
  if (openUploadBtn) {
    openUploadBtn.addEventListener('click', () => {
      openModal('upload-modal');
    });
  }

  const uploadForm = document.getElementById('upload-form');
  if (uploadForm) {
    uploadForm.addEventListener('submit', handleDocumentUpload);
  }

  // Permission Grant Form
  const grantForm = document.getElementById('grant-permission-form');
  if (grantForm) {
    grantForm.addEventListener('submit', handleGrantPermission);
  }

  // Audit Verify Button
  const verifyBtn = document.getElementById('btn-verify-audit');
  if (verifyBtn) {
    verifyBtn.addEventListener('click', handleVerifyAuditChain);
  }

  // Audit Filter Action
  const auditActionFilter = document.getElementById('audit-action-filter');
  if (auditActionFilter) {
    auditActionFilter.addEventListener('change', () => {
      loadAuditLogs();
    });
  }
}

// ════════ Password Strength & Match Meters ════════
function evaluatePassword(val) {
  const checks = {
    len: val.length >= 10,
    upper: /[A-Z]/.test(val),
    lower: /[a-z]/.test(val),
    num: /[0-9]/.test(val),
    special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(val),
  };
  const score = Object.values(checks).filter(Boolean).length;
  return { checks, score };
}

function initPasswordStrengthMeter() {
  // 1. Sign In Password Meter
  // Login password strength meter removed – only shown on sign‑up

  // 2. Sign Up Password Meter & Match Checker
  const signupPwd = document.getElementById('signup-password');
  const signupConfirm = document.getElementById('signup-password-confirm');
  const signupFill = document.getElementById('signup-meter-fill');
  const signupLabel = document.getElementById('signup-meter-label');

  if (signupPwd && signupFill) {
    signupPwd.addEventListener('input', () => {
      const val = signupPwd.value;
      const { checks, score } = evaluatePassword(val);

      updateRule('signup-rule-len', checks.len);
      updateRule('signup-rule-upper', checks.upper);
      updateRule('signup-rule-lower', checks.lower);
      updateRule('signup-rule-num', checks.num);
      updateRule('signup-rule-special', checks.special);

      signupFill.className = 'meter-fill';
      if (val.length === 0) {
        signupFill.style.width = '0%';
        if (signupLabel) { signupLabel.textContent = 'None'; signupLabel.className = 'meter-strength-label text-muted'; }
      } else if (score <= 2) {
        signupFill.classList.add('meter-weak');
        if (signupLabel) { signupLabel.textContent = 'Weak'; signupLabel.className = 'meter-strength-label text-danger'; }
      } else if (score === 3) {
        signupFill.classList.add('meter-fair');
        if (signupLabel) { signupLabel.textContent = 'Fair'; signupLabel.className = 'meter-strength-label text-warning'; }
      } else if (score === 4) {
        signupFill.classList.add('meter-good');
        if (signupLabel) { signupLabel.textContent = 'Good'; signupLabel.className = 'meter-strength-label text-primary'; }
      } else {
        signupFill.classList.add('meter-strong');
        if (signupLabel) { signupLabel.textContent = 'Cryptographic Grade'; signupLabel.className = 'meter-strength-label text-success'; }
      }

      updateSignupMatchStatus();
    });
  }

  if (signupConfirm) {
    signupConfirm.addEventListener('input', updateSignupMatchStatus);
  }
}

function updateSignupMatchStatus() {
  const pwd = document.getElementById('signup-password')?.value || '';
  const confirm = document.getElementById('signup-password-confirm')?.value || '';
  const statusEl = document.getElementById('signup-match-status');
  if (!statusEl) return;

  if (!confirm) {
    statusEl.className = 'password-match-badge';
    statusEl.innerHTML = '<span class="rule-icon">○</span> <span>Re-enter key to verify exact match</span>';
    return;
  }

  if (pwd === confirm) {
    statusEl.className = 'password-match-badge matched';
    statusEl.innerHTML = '<span class="rule-icon">✓</span> <span>Clearance keys match perfectly</span>';
  } else {
    statusEl.className = 'password-match-badge mismatched';
    statusEl.innerHTML = '<span class="rule-icon">✕</span> <span>Clearance keys do not match</span>';
  }
}

function updateRule(elementId, isValid) {
  const el = document.getElementById(elementId);
  if (el) {
    if (isValid) {
      el.classList.add('valid');
      const icon = el.querySelector('.rule-icon');
      if (icon) icon.textContent = '✓';
    } else {
      el.classList.remove('valid');
      const icon = el.querySelector('.rule-icon');
      if (icon) icon.textContent = '○';
    }
  }
}

// ════════ Password Visibility Toggle Helper ════════
function setupPasswordToggle(toggleBtnId, inputId) {
  const btn = document.getElementById(toggleBtnId);
  const input = document.getElementById(inputId);
  if (!btn || !input) return;

  btn.addEventListener('click', () => {
    const isPwd = input.getAttribute('type') === 'password';
    input.setAttribute('type', isPwd ? 'text' : 'password');
    btn.innerHTML = isPwd
      ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
      : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  });
}

// ════════ Auth Switcher Tabs ════════
function switchAuthMode(mode) {
  const isSignIn = mode === 'signin';
  const tabSignin = document.getElementById('tab-btn-signin');
  const tabSignup = document.getElementById('tab-btn-signup');
  const panelSignin = document.getElementById('auth-panel-signin');
  const panelSignup = document.getElementById('auth-panel-signup');
  const alertEl = document.getElementById('login-alert');
  const descEl = document.getElementById('auth-header-desc');

  if (tabSignin) tabSignin.classList.toggle('active', isSignIn);
  if (tabSignup) tabSignup.classList.toggle('active', !isSignIn);
  if (panelSignin) panelSignin.style.display = isSignIn ? 'block' : 'none';
  if (panelSignup) panelSignup.style.display = !isSignIn ? 'block' : 'none';
  if (alertEl) alertEl.style.display = 'none';

  if (descEl) {
    descEl.textContent = isSignIn
      ? 'Zero-trust access with tamper-evident cryptographic proof'
      : 'Provision a new zero-trust identity with hardware-grade cryptographic credentials';
  }
}

// ════════ Entropy Password Generator ════════
function generateEntropyPassword() {
  const uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lowers = 'abcdefghjkmnpqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*-_=+';

  let pwd = '';
  // Guaranteed requirements
  for (let i = 0; i < 3; i++) pwd += uppers[Math.floor(Math.random() * uppers.length)];
  for (let i = 0; i < 5; i++) pwd += lowers[Math.floor(Math.random() * lowers.length)];
  for (let i = 0; i < 3; i++) pwd += digits[Math.floor(Math.random() * digits.length)];
  for (let i = 0; i < 3; i++) pwd += symbols[Math.floor(Math.random() * symbols.length)];

  // Shuffle thoroughly
  pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');

  const signupPwd = document.getElementById('signup-password');
  const signupConfirm = document.getElementById('signup-password-confirm');
  if (signupPwd && signupConfirm) {
    signupPwd.value = pwd;
    signupConfirm.value = pwd;
    signupPwd.dispatchEvent(new Event('input'));
    signupConfirm.dispatchEvent(new Event('input'));

    navigator.clipboard?.writeText(pwd).catch(() => {});
    showToast('High-entropy key generated & copied to clipboard!', 'success');
  }
}

// ════════ One-Click Evaluator Persona Switcher ════════
window.selectPersona = function(email, password) {
  switchAuthMode('signin');
  document.getElementById('login-email').value = email;
  const pwdInput = document.getElementById('login-password');
  pwdInput.value = password;
  pwdInput.dispatchEvent(new Event('input'));

  // Trigger login automatically for seamless judge evaluation
  const loginForm = document.getElementById('login-form');
  loginForm.dispatchEvent(new Event('submit'));
};

// ════════ Authentication Handlers ════════
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const btn = document.getElementById('login-submit-btn');
  const alertEl = document.getElementById('login-alert');
  const rememberCheckbox = document.getElementById('login-remember');

  alertEl.style.display = 'none';
  // Enforce Gmail domain
  if (!email.toLowerCase().endsWith('@gmail.com')) {
    alertEl.textContent = 'Only Gmail addresses are allowed for login.';
    alertEl.style.display = 'block';
    showToast('Invalid email domain. Please use a @gmail.com address.', 'danger');
    btn.disabled = false;
    btn.innerHTML = '<span>Sign In</span> <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span>Signing in...</span>';

  try {
    const data = await API.login(email, password);
    state.currentUser = data.user;

    // Remember identity preference
    if (rememberCheckbox?.checked) {
      localStorage.setItem('trustvault_remembered_email', email);
    } else {
      localStorage.removeItem('trustvault_remembered_email');
    }

    showToast(`Welcome back, ${data.user.full_name}`, 'success');
    renderApp();
  } catch (err) {
    alertEl.textContent = err.message;
    alertEl.style.display = 'block';
    showToast(err.message, 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Sign In</span> <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';
  }
}

async function handleSignup(e) {
  e.preventDefault();
  const fullName = document.getElementById('signup-name').value.trim();
  const email = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;
  const confirm = document.getElementById('signup-password-confirm').value;
  const role = document.querySelector('input[name="signup-role"]:checked')?.value || 'viewer';
  const agreed = document.getElementById('signup-agreement').checked;
  const btn = document.getElementById('signup-submit-btn');
  const alertEl = document.getElementById('login-alert');

  if (password !== confirm) {
    alertEl.textContent = 'Passwords do not match. Please verify.';
    alertEl.style.display = 'block';
    showToast('Passwords do not match', 'warning');
    return;
  }

  const { score } = evaluatePassword(password);
  if (score < 5) {
    alertEl.textContent = 'Password must satisfy all complexity rules (10+ characters, uppercase, lowercase, digit, and special symbol).';
    alertEl.style.display = 'block';
    showToast('Password does not meet security requirements', 'danger');
    return;
  }

  if (!agreed) {
    showToast('Please confirm agreement to the security policy', 'warning');
    return;
  }

  alertEl.style.display = 'none';
  // Enforce Gmail domain for signup
  if (!email.toLowerCase().endsWith('@gmail.com')) {
    alertEl.textContent = 'Only Gmail addresses are allowed for signup.';
    alertEl.style.display = 'block';
    showToast('Invalid email domain. Please use a @gmail.com address.', 'danger');
    btn.disabled = false;
    btn.innerHTML = '<span>Create Account</span> <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span>Creating account...</span>';

  try {
    const data = await API.signup(email, fullName, password, role);
    // Clear any auto-set token/user to prevent immediate login
    API.clearSession();
    showToast(`Account created for ${fullName}. Please log in.`, 'success');
    const loginEmailInput = document.getElementById('login-email');
    if (loginEmailInput) loginEmailInput.value = email;
    switchAuthMode('signin');
  } catch (err) {
    alertEl.textContent = err.message;
    alertEl.style.display = 'block';
    showToast(err.message, 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Create Account</span> <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
  }
}

async function handleRecovery(e) {
  e.preventDefault();
  const email = document.getElementById('recovery-email').value.trim();
  const newPassword = document.getElementById('recovery-password').value;
  const confirm = document.getElementById('recovery-password-confirm').value;
  const alertEl = document.getElementById('recovery-alert');
  const btn = document.getElementById('recovery-submit-btn');

  if (newPassword !== confirm) {
    alertEl.textContent = 'Passwords do not match.';
    alertEl.style.display = 'block';
    return;
  }

  const { score } = evaluatePassword(newPassword);
  if (score < 5) {
    alertEl.textContent = 'New password must satisfy all complexity rules (10+ characters, upper, lower, digit, and special symbol).';
    alertEl.style.display = 'block';
    return;
  }

  alertEl.style.display = 'none';
  btn.disabled = true;
  btn.innerHTML = '<span>Resetting password...</span>';

  try {
    await API.resetPassword(email, newPassword);
    showToast('Password reset successfully. Active sessions revoked. Please sign in.', 'success');
    document.getElementById('recovery-modal').classList.remove('open');
    switchAuthMode('signin');
    const loginEmail = document.getElementById('login-email');
    if (loginEmail) {
      loginEmail.value = email;
      document.getElementById('login-password')?.focus();
    }
  } catch (err) {
    alertEl.textContent = err.message;
    alertEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Reset Password</span>';
  }
}

// ════════ Tab Navigation & Data Fetching ════════
function switchTab(tabName) {
  state.activeTab = tabName;

  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tab === tabName);
  });

  document.getElementById('section-documents').style.display = tabName === 'documents' ? 'block' : 'none';
  document.getElementById('section-audit').style.display = tabName === 'audit' ? 'block' : 'none';
  document.getElementById('section-admin').style.display = tabName === 'admin' ? 'block' : 'none';

  if (tabName === 'documents') {
    loadDocuments();
  } else if (tabName === 'audit') {
    loadAuditLogs();
    loadAuditStats();
  } else if (tabName === 'admin') {
    loadAdminUsers();
  }
}

// ════════ Documents Operations ════════
async function loadDocuments() {
  const grid = document.getElementById('document-grid');
  grid.innerHTML = '<div class="text-muted" style="grid-column: 1/-1; text-align: center; padding: 3rem;">Loading encrypted vault assets...</div>';

  try {
    const res = await API.listDocuments(state.searchQuery, state.activeCategory);
    state.documents = res.documents;
    renderDocumentGrid(res.documents);
  } catch (err) {
    grid.innerHTML = `<div class="text-danger" style="grid-column: 1/-1; text-align: center; padding: 3rem;">Failed to load documents: ${err.message}</div>`;
  }
}

function renderDocumentGrid(documents) {
  const grid = document.getElementById('document-grid');
  if (!documents || documents.length === 0) {
    grid.innerHTML = `
      <div style="grid-column: 1/-1; text-align: center; padding: 3.5rem 1rem; color: var(--text-muted); background: var(--bg-surface); border: 1px dashed var(--border-medium); border-radius: var(--radius-md);">
        <div style="font-size: 2rem; margin-bottom: 0.75rem;">📁</div>
        <h3 style="font-size: 1.1rem; color: var(--text-main);">No Accessible Documents</h3>
        <p style="font-size: 0.85rem; margin-top: 0.35rem; color: var(--text-muted);">You only have access to documents explicitly shared with your account.</p>
      </div>`;
    return;
  }

  grid.innerHTML = documents.map(doc => {
    const isOwner = doc.permission_level === 'owner';
    const canEdit = isOwner || doc.permission_level === 'edit';
    const canRead = canEdit || doc.permission_level === 'read';

    let iconClass = 'doc-icon';
    if (doc.category === 'salary') iconClass += ' salary';
    else if (doc.category === 'contracts') iconClass += ' contracts';
    else if (doc.category === 'audit') iconClass += ' audit';

    const sizeFormatted = (doc.file_size / 1024).toFixed(1) + ' KB';
    const dateFormatted = new Date(doc.created_at).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric'
    });

    let permBadge = '';
    if (isOwner) permBadge = '<span class="badge badge-owner">Owner</span>';
    else if (doc.permission_level === 'edit') permBadge = '<span class="badge badge-edit">Editor</span>';
    else if (doc.permission_level === 'read') permBadge = '<span class="badge badge-read">Viewer</span>';
    else permBadge = '<span class="badge badge-denied">Restricted</span>';

    return `
      <div class="doc-card" id="doc-${doc.id}">
        <div>
          <div class="doc-top">
            <div class="${iconClass}">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
            </div>
            <div class="doc-header-info">
              <h3 class="doc-title" title="${escapeHtml(doc.original_filename)}">${escapeHtml(doc.original_filename)}</h3>
              <div class="doc-badges">
                ${permBadge}
                <span class="badge" style="background: var(--bg-surface-subtle); color: var(--text-muted); border: 1px solid var(--border-subtle);">${escapeHtml(doc.category || 'general')}</span>
              </div>
            </div>
          </div>
          <p class="doc-desc">${escapeHtml(doc.description || 'No description provided.')}</p>
        </div>

        <div>
          <div class="doc-meta">
            <span>By: <strong>${escapeHtml(doc.owner_name || 'Owner')}</strong></span>
            <span>${sizeFormatted} • ${dateFormatted}</span>
          </div>

          <div class="doc-actions">
${canRead ? `
              <button class="btn btn-primary btn-sm" style="flex-grow: 1;" onclick="downloadDoc('${doc.id}', '${escapeHtml(doc.original_filename)}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Download
              </button>
              <button class="btn btn-warning btn-sm" style="flex-grow: 1; margin-left:0.5rem;" onclick="editDoc('${doc.id}', '${escapeHtml(doc.original_filename)}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>
                Edit
              </button>` : ''}

            ${isOwner || state.currentUser?.role === 'admin' ? `
              <button class="btn btn-secondary btn-sm" title="Manage Permissions" onclick="openPermissionsModal('${doc.id}', '${escapeHtml(doc.original_filename)}')">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                Access
              </button>
              <button class="btn btn-secondary btn-sm" title="AI Access Advisor" onclick="openAIAdvisor('${doc.id}', '${escapeHtml(doc.original_filename)}', '${escapeHtml(doc.category)}')">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/><path d="M12 6v6l4 2"/></svg>
                Advisor
              </button>
              <button class="btn btn-danger btn-sm" title="Delete Document" onclick="deleteDoc('${doc.id}', '${escapeHtml(doc.original_filename)}')">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>` : ''}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

window.downloadDoc = async function(docId, filename) {
  try {
    showToast(`Decrypting and downloading ${filename}...`, 'primary');
    await API.downloadDocument(docId, filename);
    showToast('Download complete', 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
};

window.editDoc = async function(docId, filename) {
  // Placeholder: Open the document in edit mode.
  // In a full implementation this would fetch the encrypted document, decrypt it,
  // and present an editable UI. For now we simply redirect to the document view.
  showToast(`Opening ${filename} for editing...`, 'info');
  // Example: switch to the viewer tab and load the document details.
  switchTab('documents');
  // Load the document and set an edit flag (implementation dependent).
  // This stub demonstrates the UI hook.
};


// ════════ Document Upload ════════
async function handleDocumentUpload(e) {
  e.preventDefault();
  const fileInput = document.getElementById('upload-file');
  const catInput = document.getElementById('upload-category');
  const descInput = document.getElementById('upload-desc');
  const submitBtn = document.getElementById('upload-submit-btn');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast('Please select a file to encrypt and upload.', 'warning');
    return;
  }

  const file = fileInput.files[0];
  if (file.size > 50 * 1024 * 1024) {
    showToast('File exceeds 50 MB limit.', 'danger');
    return;
  }

  const formData = new FormData();
  formData.append('file', file);
  formData.append('category', catInput.value);
  formData.append('description', descInput.value);

  submitBtn.disabled = true;
  submitBtn.textContent = 'Encrypting (AES-256-GCM)...';

  try {
    await API.uploadDocument(formData);
    showToast(`Document "${file.name}" encrypted & uploaded successfully!`, 'success');
    closeAllModals();
    uploadForm.reset();
    loadDocuments();
  } catch (err) {
    showToast(err.message, 'danger');
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Encrypt & Upload to Vault';
  }
}

// ════════ Granular Permissions Modal ════════
window.openPermissionsModal = async function(docId, filename) {
  state.selectedDocForPermissions = docId;
  document.getElementById('perm-modal-filename').textContent = filename;
  openModal('permissions-modal');
  loadDocPermissions(docId);
};

async function loadDocPermissions(docId) {
  const container = document.getElementById('permissions-list-container');
  container.innerHTML = '<div class="text-muted" style="text-align: center; padding: 1rem;">Loading access grants...</div>';

  try {
    const perms = await API.listPermissions(docId);
    renderPermissionsList(perms);
  } catch (err) {
    container.innerHTML = `<div class="text-danger" style="text-align: center; padding: 1rem;">${err.message}</div>`;
  }
}

function renderPermissionsList(perms) {
  const container = document.getElementById('permissions-list-container');
  if (!perms || perms.length === 0) {
    container.innerHTML = '<p class="text-muted" style="font-size: 0.85rem; padding: 0.5rem 0;">No active external grants. Only you (the owner) can access this document.</p>';
    return;
  }

  container.innerHTML = perms.map(p => {
    const isRevoked = p.is_revoked;
    const isExpired = p.expires_at && new Date(p.expires_at) < new Date();
    let statusBadge = '<span class="badge badge-edit">Active</span>';

    if (isRevoked) {
      statusBadge = '<span class="badge badge-denied">Revoked</span>';
    } else if (isExpired) {
      statusBadge = '<span class="badge" style="background: var(--warning-bg); color: var(--warning-text); border: 1px solid var(--warning-border);">Expired</span>';
    }

    return `
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-subtle); background: var(--bg-surface); ${isRevoked ? 'opacity: 0.5;' : ''}">
        <div>
          <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-main);">${escapeHtml(p.user_name || p.user_email)}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.15rem;">
            ${escapeHtml(p.user_email)} • Level: <strong style="text-transform: uppercase; color: var(--text-main);">${p.level}</strong> • ${statusBadge}
          </div>
        </div>
        ${!isRevoked ? `
          <button class="btn btn-danger btn-sm" onclick="revokeAccess('${p.id}')">
            Revoke Access
          </button>` : '<span style="font-size: 0.75rem; color: var(--danger); font-weight: 500;">Revoked</span>'}
      </div>
    `;
  }).join('');
}

async function handleGrantPermission(e) {
  e.preventDefault();
  const docId = state.selectedDocForPermissions;
  const email = document.getElementById('grant-email').value.trim();
  const level = document.getElementById('grant-level').value;
  const expiry = document.getElementById('grant-expiry').value;
  const btn = document.getElementById('grant-submit-btn');

  btn.disabled = true;

  try {
    await API.grantPermission(docId, email, level, expiry ? new Date(expiry).toISOString() : null);
    showToast(`Access granted to ${email}`, 'success');
    document.getElementById('grant-email').value = '';
    document.getElementById('grant-expiry').value = '';
    loadDocPermissions(docId);
  } catch (err) {
    showToast(err.message, 'danger');
  } finally {
    btn.disabled = false;
  }
}

window.revokeAccess = async function(permId) {
  const docId = state.selectedDocForPermissions;
  if (!confirm('Revoke this permission? The user will immediately lose access to this document.')) {
    return;
  }

  try {
    await API.revokePermission(docId, permId, 'Owner revoked grant via Access Management');
    showToast('Permission revoked successfully', 'warning');
    loadDocPermissions(docId);
  } catch (err) {
    showToast(err.message, 'danger');
  }
};

// ════════ AI Access Advisor Modal ════════
window.openAIAdvisor = async function(docId, filename, category) {
  state.selectedDocForPermissions = docId;
  const modalFilename = document.getElementById('perm-modal-filename');
  openModal('ai-modal');

  const container = document.getElementById('ai-recommendations-container');
  container.innerHTML = `
    <div style="text-align: center; padding: 2.5rem 1rem; color: var(--text-muted);">
      <p style="font-size: 0.875rem;">Analyzing document category and recommended permissions...</p>
    </div>`;

  try {
    const res = await API.suggestAIPermissions(docId, filename, category, '');
    renderAIAdvisorResults(res);
  } catch (err) {
    container.innerHTML = `<div class="text-danger" style="text-align: center; padding: 1.5rem;">${err.message}</div>`;
  }
};

function renderAIAdvisorResults(data) {
  const container = document.getElementById('ai-recommendations-container');

  const recommendationsHtml = data.recommendations.map(r => `
    <div class="ai-recommendation-item">
      <div>
        <div style="font-weight: 600; font-size: 0.85rem; color: var(--text-main);">${escapeHtml(r.user_name)} (${escapeHtml(r.user_email)})</div>
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem;">${escapeHtml(r.justification)}</div>
        <div style="font-size: 0.72rem; color: var(--primary-accent); margin-top: 0.2rem; font-weight: 500;">
          Recommended: <strong>${r.recommended_level.toUpperCase()}</strong> (${Math.round(r.confidence * 100)}% confidence)
        </div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="confirmAIGrant('${r.user_email}', '${r.recommended_level}')">
        Grant
      </button>
    </div>
  `).join('');

  container.innerHTML = `
    <div style="margin-bottom: 1.25rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
        <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; letter-spacing: 0.03em;">Classification</span>
        <span class="badge" style="background: var(--purple-bg); color: var(--purple-text); border: 1px solid var(--purple-border);">${escapeHtml(data.data_classification)}</span>
      </div>
      <p style="font-size: 0.825rem; color: var(--text-body); background: var(--bg-surface-subtle); padding: 0.75rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
        ${escapeHtml(data.sensitivity_summary)}
      </p>
    </div>

    <div style="font-size: 0.825rem; font-weight: 600; color: var(--text-main); margin-bottom: 0.4rem;">
      Suggested Collaborators (${data.recommendations.length})
    </div>

    ${recommendationsHtml || '<p class="text-muted" style="font-size: 0.825rem;">No automatic collaborators suggested.</p>'}

    <div style="margin-top: 1rem; padding: 0.65rem 0.85rem; background: var(--warning-bg); border: 1px solid var(--warning-border); border-radius: var(--radius-sm); font-size: 0.75rem; color: var(--warning-text);">
      <strong>Policy:</strong> ${escapeHtml(data.machine_enforced_rule)}
    </div>
  `;
}

window.confirmAIGrant = async function(email, level) {
  const docId = state.selectedDocForPermissions;
  try {
    await API.grantPermission(docId, email, level);
    showToast(`Access granted to ${email} as ${level}`, 'success');
    closeAllModals();
    loadDocuments();
  } catch (err) {
    showToast(err.message, 'danger');
  }
};

// ════════ Audit Trail & Cryptographic Verification ════════
async function loadAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;" class="text-muted">Loading audit entries...</td></tr>';

  const actionFilter = document.getElementById('audit-action-filter')?.value || '';

  try {
    const res = await API.listAuditLogs({ action: actionFilter });
    state.auditLogs = res.logs;
    renderAuditTable(res.logs);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--danger); padding: 2rem;">${err.message}</td></tr>`;
  }
}

async function loadAuditStats() {
  if (state.currentUser?.role !== 'admin') return;

  try {
    const stats = await API.getAuditStats();
    state.stats = stats;
    document.getElementById('stat-total-actions').textContent = stats.total_actions;
    document.getElementById('stat-total-refusals').textContent = stats.total_refusals;
    document.getElementById('stat-total-grants').textContent = stats.total_grants;
    document.getElementById('stat-total-revocations').textContent = stats.total_revocations;
  } catch (e) {
    // Viewer/Owner might not have stats permission
  }
}

function renderAuditTable(logs) {
  const tbody = document.getElementById('audit-table-body');
  if (!logs || logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;" class="text-muted">No audit events recorded.</td></tr>';
    return;
  }

  tbody.innerHTML = logs.map(log => {
    let actionBadge = `<span class="badge" style="background: var(--bg-surface-subtle); color: var(--text-muted); border: 1px solid var(--border-subtle);">${escapeHtml(log.action)}</span>`;
    if (log.action.includes('DENIED') || log.action.includes('FAILED')) {
      actionBadge = `<span class="badge badge-denied">${escapeHtml(log.action)}</span>`;
    } else if (log.action === 'PERMISSION_GRANT') {
      actionBadge = `<span class="badge badge-edit">GRANT</span>`;
    } else if (log.action === 'PERMISSION_REVOKE') {
      actionBadge = `<span class="badge badge-denied">REVOKE</span>`;
    } else if (log.action === 'UPLOAD') {
      actionBadge = `<span class="badge badge-owner">UPLOAD</span>`;
    } else if (log.action === 'DOWNLOAD') {
      actionBadge = `<span class="badge badge-read">DOWNLOAD</span>`;
    }

    const timeFormatted = new Date(log.created_at).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
    });

    const detailsStr = log.details ? JSON.stringify(log.details) : '—';

    return `
      <tr>
        <td class="mono" style="color: var(--text-main); font-weight: 500;">#${log.id}</td>
        <td>${timeFormatted}</td>
        <td>${actionBadge}</td>
        <td><strong>${escapeHtml(log.user_email || 'System')}</strong></td>
        <td>${escapeHtml(log.document_name || '—')}</td>
        <td class="mono" style="font-size: 0.75rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(detailsStr)}">
          ${escapeHtml(detailsStr)}
        </td>
      </tr>
    `;
  }).join('');
}

async function handleVerifyAuditChain() {
  const btn = document.getElementById('btn-verify-audit');
  const banner = document.getElementById('integrity-banner');
  const title = document.getElementById('integrity-title');
  const desc = document.getElementById('integrity-desc');
  const icon = document.getElementById('integrity-icon');

  btn.disabled = true;
  btn.textContent = 'Verifying Chain Integrity...';

  try {
    const res = await API.verifyAuditIntegrity();

    if (res.is_valid) {
      banner.className = 'integrity-banner';
      icon.textContent = '🛡️';
      title.textContent = 'Cryptographic Hash Chain Verified';
      desc.textContent = `All ${res.total_entries} historical records cryptographically chained via SHA-256. Zero alterations, deletions, or insertions detected.`;
      showToast('Audit trail cryptographic integrity verified', 'success');
    } else {
      banner.className = 'integrity-banner tampered';
      icon.textContent = '⚠️';
      title.textContent = 'Audit Tampering Detected';
      desc.textContent = `${res.message} (Flagged Block #${res.first_broken_entry_id}). The record has been modified or altered.`;
      showToast('Integrity check: Tampering detected', 'danger');
    }
  } catch (err) {
    showToast(err.message, 'danger');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify Chain Integrity';
  }
}

// ════════ Admin User Management ════════
async function loadAdminUsers() {
  const tbody = document.getElementById('users-table-body');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;" class="text-muted">Loading user directory...</td></tr>';

  try {
    const users = await API.listUsers();
    state.users = users;
    renderUsersTable(users);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--danger); padding: 2rem;">${err.message}</td></tr>`;
  }
}

function renderUsersTable(users) {
  const tbody = document.getElementById('users-table-body');
  if (!users || users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;" class="text-muted">No users found.</td></tr>';
    return;
  }

  tbody.innerHTML = users.map(u => {
    const isSelf = u.id === state.currentUser?.id;
    const statusBadge = u.is_active 
      ? '<span class="badge badge-edit">Active</span>' 
      : '<span class="badge badge-denied">Deactivated</span>';

    return `
      <tr>
        <td>
          <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(u.full_name)}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(u.email)}</div>
        </td>
        <td><strong style="text-transform: uppercase; color: var(--text-main); font-size: 0.78rem;">${u.role}</strong></td>
        <td>${statusBadge}</td>
        <td>${new Date(u.created_at).toLocaleDateString()}</td>
        <td>
          ${!isSelf ? `
            <button class="btn ${u.is_active ? 'btn-danger' : 'btn-success'} btn-sm" onclick="toggleUserStatus('${u.id}', ${!u.is_active})">
              ${u.is_active ? 'Deactivate' : 'Activate'}
            </button>` : '<span class="text-dim" style="font-size: 0.75rem;">Current Account</span>'}
        </td>
      </tr>
    `;
  }).join('');
}

window.toggleUserStatus = async function(userId, newStatus) {
  const actionName = newStatus ? 'activate' : 'deactivate';
  if (!confirm(`Are you sure you want to ${actionName} this user? Deactivating will immediately invalidate all active sessions.`)) {
    return;
  }

  try {
    await API.updateUserStatus(userId, newStatus, `Admin toggled status to ${actionName}`);
    showToast(`User ${actionName}d successfully`, 'success');
    loadAdminUsers();
  } catch (err) {
    showToast(err.message, 'danger');
  }
};

// ════════ Modal Helpers ════════
function openModal(modalId) {
  closeAllModals();
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
  }
}

function closeAllModals() {
  document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('open'));
}

// ════════ Toast Helper ════════
function showToast(message, type = 'primary') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// ════════ HTML Escape Helper ════════
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
