/**
 * TrustVault API Client
 * Manages JWT tokens, automatic refresh, authorization headers, and error handling.
 */

const API = {
  baseUrl: '',

  getToken() {
    return localStorage.getItem('trustvault_token');
  },

  setToken(token) {
    if (token) {
      localStorage.setItem('trustvault_token', token);
    } else {
      localStorage.removeItem('trustvault_token');
    }
  },

  getUser() {
    const raw = localStorage.getItem('trustvault_user');
    return raw ? JSON.parse(raw) : null;
  },

  setUser(user) {
    if (user) {
      localStorage.setItem('trustvault_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('trustvault_user');
    }
  },

  async request(endpoint, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    options.headers = headers;
    options.credentials = 'same-origin'; // for cookies

    try {
      const response = await fetch(endpoint, options);

      // Handle 401 Unauthorized / Token Revocation
      if (response.status === 401) {
        // Attempt token refresh if not already calling auth
        if (!endpoint.includes('/api/auth/')) {
          const refreshed = await this.refreshToken();
          if (refreshed) {
            headers['Authorization'] = `Bearer ${this.getToken()}`;
            return fetch(endpoint, options);
          }
        }
        this.clearSession();
        window.dispatchEvent(new CustomEvent('auth:expired'));
        throw new Error('Session expired or revoked. Please log in again.');
      }

      if (response.status === 429) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Rate limit exceeded. Please wait 60 seconds.');
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(errorData.detail || `Error: ${response.statusText}`);
      }

      // Check if response is JSON
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }

      return response;
    } catch (err) {
      throw err;
    }
  },

  async login(email, password) {
    const data = await this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  },

  async signup(email, fullName, password, role = 'viewer') {
    const data = await this.request('/api/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ email, full_name: fullName, password, role }),
    });

    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  },

  async resetPassword(email, newPassword) {
    return await this.request('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, new_password: newPassword }),
    });
  },

  async refreshToken() {
    try {
      const res = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        this.setToken(data.access_token);
        return true;
      }
    } catch (e) {
      // Refresh failed
    }
    return false;
  },

  async logout() {
    try {
      await this.request('/api/auth/logout', { method: 'POST' });
    } catch (e) {
      // Ignore network errors on logout
    } finally {
      this.clearSession();
    }
  },

  clearSession() {
    this.setToken(null);
    this.setUser(null);
  },

  async getCurrentUser() {
    return await this.request('/api/auth/me');
  },

  // Document Operations
  async listDocuments(query = '', category = '') {
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (category && category !== 'all') params.append('category', category);
    return await this.request(`/api/documents?${params.toString()}`);
  },

  async uploadDocument(formData) {
    return await this.request('/api/documents', {
      method: 'POST',
      body: formData,
    });
  },

  async downloadDocument(documentId, filename) {
    const token = this.getToken();
    const response = await fetch(`/api/documents/${documentId}/download`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ detail: 'Download failed' }));
      throw new Error(err.detail || 'Download forbidden or file not found.');
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);
  },

  async deleteDocument(documentId) {
    return await this.request(`/api/documents/${documentId}`, {
      method: 'DELETE',
    });
  },

  // Permissions Operations
  async listPermissions(documentId) {
    return await this.request(`/api/documents/${documentId}/permissions`);
  },

  async grantPermission(documentId, userEmail, level = 'read', expiresAt = null) {
    return await this.request(`/api/documents/${documentId}/permissions`, {
      method: 'POST',
      body: JSON.stringify({
        user_email: userEmail,
        level: level,
        expires_at: expiresAt || null,
      }),
    });
  },

  async revokePermission(documentId, permissionId, reason = '') {
    return await this.request(`/api/documents/${documentId}/permissions/${permissionId}`, {
      method: 'DELETE',
      body: JSON.stringify({ reason }),
    });
  },

  // Audit Operations
  async listAuditLogs(filters = {}) {
    const params = new URLSearchParams();
    if (filters.action) params.append('action', filters.action);
    if (filters.documentId) params.append('document_id', filters.documentId);
    if (filters.page) params.append('page', filters.page);
    return await this.request(`/api/audit?${params.toString()}`);
  },

  async verifyAuditIntegrity() {
    return await this.request('/api/audit/verify');
  },

  async getAuditStats() {
    return await this.request('/api/audit/stats');
  },

  // Users & Admin
  async listUsers() {
    return await this.request('/api/users');
  },

  async updateUserStatus(userId, isActive, reason = '') {
    return await this.request(`/api/users/${userId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ is_active: isActive, reason }),
    });
  },

  // AI Access Advisor
  async suggestAIPermissions(documentId, title, category, description) {
    return await this.request('/api/ai/suggest-permissions', {
      method: 'POST',
      body: JSON.stringify({
        document_id: documentId,
        title: title,
        category: category,
        description: description,
      }),
    });
  }
};
