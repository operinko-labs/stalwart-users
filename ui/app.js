// Configuration
window.API_BASE = window.location.pathname.startsWith('/manage/users') ? '../api' : '';

// DOM Elements
const elements = {
    loginSection: document.getElementById('login-section'),
    mainSection: document.getElementById('main-section'),
    tokenInput: document.getElementById('token-input'),
    btnSaveToken: document.getElementById('btn-save-token'),
    btnClearToken: document.getElementById('btn-clear-token'),
    bannerContainer: document.getElementById('banner-container'),
    
    // Tabs
    tabs: document.querySelectorAll('.tab'),
    tabContents: document.querySelectorAll('.tab-content'),
    
    // Accounts
    accountsTbody: document.getElementById('accounts-tbody'),
    btnShowCreateAccount: document.getElementById('btn-show-create-account'),
    createAccountContainer: document.getElementById('create-account-container'),
    formCreateAccount: document.getElementById('form-create-account'),
    btnCancelCreateAccount: document.getElementById('btn-cancel-create-account'),
    
    // Aliases
    aliasAccountSelect: document.getElementById('alias-account-select'),
    aliasesContent: document.getElementById('aliases-content'),
    aliasesEmptyState: document.getElementById('aliases-empty-state'),
    aliasesTbody: document.getElementById('aliases-tbody'),
    btnShowAddAlias: document.getElementById('btn-show-add-alias'),
    addAliasContainer: document.getElementById('add-alias-container'),
    formAddAlias: document.getElementById('form-add-alias'),
    btnCancelAddAlias: document.getElementById('btn-cancel-add-alias'),
    
    // Groups
    groupAccountSelect: document.getElementById('group-account-select'),
    groupsContent: document.getElementById('groups-content'),
    groupsEmptyState: document.getElementById('groups-empty-state'),
    groupsTbody: document.getElementById('groups-tbody'),
    btnShowAddGroup: document.getElementById('btn-show-add-group'),
    addGroupContainer: document.getElementById('add-group-container'),
    formAddGroup: document.getElementById('form-add-group'),
    btnCancelAddGroup: document.getElementById('btn-cancel-add-group')
};

// State
let currentToken = localStorage.getItem('token') || '';

// Initialize
function init() {
    setupEventListeners();
    checkAuth();
}

// Event Listeners
function setupEventListeners() {
    // Auth
    elements.btnSaveToken.addEventListener('click', handleSaveToken);
    elements.btnClearToken.addEventListener('click', handleClearToken);
    elements.tokenInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleSaveToken();
    });

    // Tabs
    elements.tabs.forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.target));
    });

    // Accounts
    elements.btnShowCreateAccount.addEventListener('click', () => {
        elements.createAccountContainer.classList.remove('hidden');
        elements.btnShowCreateAccount.classList.add('hidden');
    });

    elements.btnCancelCreateAccount.addEventListener('click', () => {
        elements.createAccountContainer.classList.add('hidden');
        elements.btnShowCreateAccount.classList.remove('hidden');
        elements.formCreateAccount.reset();
    });

    elements.formCreateAccount.addEventListener('submit', handleCreateAccount);

    // Aliases
    elements.aliasAccountSelect.addEventListener('change', (e) => {
        const accountName = e.target.value;
        if (accountName) {
            elements.aliasesEmptyState.classList.add('hidden');
            elements.aliasesContent.classList.remove('hidden');
            loadEmails(accountName);
        } else {
            elements.aliasesEmptyState.classList.remove('hidden');
            elements.aliasesContent.classList.add('hidden');
        }
    });

    elements.btnShowAddAlias.addEventListener('click', () => {
        elements.addAliasContainer.classList.remove('hidden');
        elements.btnShowAddAlias.classList.add('hidden');
    });

    elements.btnCancelAddAlias.addEventListener('click', () => {
        elements.addAliasContainer.classList.add('hidden');
        elements.btnShowAddAlias.classList.remove('hidden');
        elements.formAddAlias.reset();
    });

    elements.formAddAlias.addEventListener('submit', handleAddAlias);

    // Groups
    elements.groupAccountSelect.addEventListener('change', (e) => {
        const accountName = e.target.value;
        if (accountName) {
            elements.groupsEmptyState.classList.add('hidden');
            elements.groupsContent.classList.remove('hidden');
            loadGroups(accountName);
        } else {
            elements.groupsEmptyState.classList.remove('hidden');
            elements.groupsContent.classList.add('hidden');
        }
    });

    elements.btnShowAddGroup.addEventListener('click', () => {
        elements.addGroupContainer.classList.remove('hidden');
        elements.btnShowAddGroup.classList.add('hidden');
    });

    elements.btnCancelAddGroup.addEventListener('click', () => {
        elements.addGroupContainer.classList.add('hidden');
        elements.btnShowAddGroup.classList.remove('hidden');
        elements.formAddGroup.reset();
    });

    elements.formAddGroup.addEventListener('submit', handleAddGroup);
}

// Auth Management
function checkAuth() {
    if (currentToken) {
        elements.loginSection.classList.add('hidden');
        elements.mainSection.classList.remove('hidden');
        elements.btnClearToken.classList.remove('hidden');
        loadAccounts();
    } else {
        elements.loginSection.classList.remove('hidden');
        elements.mainSection.classList.add('hidden');
        elements.btnClearToken.classList.add('hidden');
    }
}

function handleSaveToken() {
    const token = elements.tokenInput.value.trim();
    if (token) {
        currentToken = token;
        localStorage.setItem('token', token);
        elements.tokenInput.value = '';
        checkAuth();
        showSuccess('Token saved successfully');
    } else {
        showError('Please enter a valid token');
    }
}

function handleClearToken() {
    currentToken = '';
    localStorage.removeItem('token');
    checkAuth();
    showSuccess('Logged out successfully');
}

// API Wrapper
async function fetchAPI(path, options = {}) {
    const url = `${window.API_BASE}${path}`;
    
    const headers = {
        'Authorization': `Bearer ${currentToken}`,
        ...options.headers
    };

    if (options.method && ['POST', 'PATCH', 'PUT'].includes(options.method.toUpperCase())) {
        headers['Content-Type'] = 'application/json';
    }

    try {
        const response = await fetch(url, { ...options, headers });
        
        if (response.status === 401) {
            handleClearToken();
            showError('Authentication failed. Please check your token.');
            throw new Error('Unauthorized');
        }
        
        if (!response.ok) {
            let errorMsg = `API Error: ${response.status} ${response.statusText}`;
            try {
                const errorData = await response.json();
                if (errorData.error) errorMsg = errorData.error;
            } catch (e) {
                // Ignore JSON parse error
            }
            throw new Error(errorMsg);
        }
        
        // 204 No Content doesn't have a body
        if (response.status === 204) {
            return null;
        }
        
        return await response.json();
    } catch (error) {
        if (error.message !== 'Unauthorized') {
            showError(error.message);
        }
        throw error;
    }
}

// UI Helpers
function showBanner(message, type) {
    const banner = document.createElement('div');
    banner.className = `banner banner-${type}`;
    
    const text = document.createElement('span');
    text.textContent = message;
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'banner-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = () => banner.remove();
    
    banner.appendChild(text);
    banner.appendChild(closeBtn);
    
    elements.bannerContainer.appendChild(banner);
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (banner.parentNode) {
            banner.remove();
        }
    }, 5000);
}

function showError(message) {
    showBanner(message, 'error');
}

function showSuccess(message) {
    showBanner(message, 'success');
}

function switchTab(targetId) {
    // Update tab buttons
    elements.tabs.forEach(tab => {
        if (tab.dataset.target === targetId) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    // Update tab contents
    elements.tabContents.forEach(content => {
        if (content.id === `tab-${targetId}`) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });

    if (targetId === 'aliases') {
        loadAccountsForSelect(elements.aliasAccountSelect);
    } else if (targetId === 'groups') {
        loadAccountsForSelect(elements.groupAccountSelect);
    }
}

// Accounts Management
async function loadAccounts() {
    try {
        const accounts = await fetchAPI('/accounts');
        renderAccountsTable(accounts);
    } catch (error) {
        console.error('Failed to load accounts:', error);
    }
}

function renderAccountsTable(accounts) {
    elements.accountsTbody.innerHTML = '';
    
    if (!accounts || accounts.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="6" class="text-center text-muted">No accounts found</td>`;
        elements.accountsTbody.appendChild(tr);
        return;
    }
    
    accounts.forEach(account => {
        const tr = document.createElement('tr');
        
        const activeBadgeClass = account.active ? 'badge-success' : 'badge-inactive';
        const activeBadgeText = account.active ? 'Active' : 'Inactive';
        
        tr.innerHTML = `
            <td><strong>${escapeHTML(account.name)}</strong></td>
            <td>${escapeHTML(account.description || '-')}</td>
            <td>${escapeHTML(account.type)}</td>
            <td>${formatBytes(account.quota)}</td>
            <td><span class="badge ${activeBadgeClass}">${activeBadgeText}</span></td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-outlined btn-toggle" data-name="${escapeHTML(account.name)}" data-active="${account.active}">
                        ${account.active ? 'Disable' : 'Enable'}
                    </button>
                    <button class="btn btn-sm btn-danger btn-delete" data-name="${escapeHTML(account.name)}">
                        Delete
                    </button>
                </div>
            </td>
        `;
        
        elements.accountsTbody.appendChild(tr);
    });
    
    // Add event listeners to new buttons
    document.querySelectorAll('.btn-toggle').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const name = e.target.dataset.name;
            const currentActive = e.target.dataset.active === 'true';
            toggleAccount(name, currentActive);
        });
    });
    
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const name = e.target.dataset.name;
            deleteAccount(name);
        });
    });
}

async function handleCreateAccount(e) {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('acc-name').value,
        password: document.getElementById('acc-password').value,
        description: document.getElementById('acc-description').value,
        type: document.getElementById('acc-type').value,
        quota: parseInt(document.getElementById('acc-quota').value, 10) || 0
    };
    
    try {
        await fetchAPI('/accounts', {
            method: 'POST',
            body: JSON.stringify(formData)
        });
        
        showSuccess(`Account ${formData.name} created successfully`);
        elements.formCreateAccount.reset();
        elements.createAccountContainer.classList.add('hidden');
        elements.btnShowCreateAccount.classList.remove('hidden');
        
        loadAccounts();
    } catch (error) {
        console.error('Failed to create account:', error);
    }
}

async function toggleAccount(name, currentActive) {
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(name)}`, {
            method: 'PATCH',
            body: JSON.stringify({ active: !currentActive })
        });
        
        showSuccess(`Account ${name} ${!currentActive ? 'enabled' : 'disabled'} successfully`);
        loadAccounts();
    } catch (error) {
        console.error('Failed to toggle account:', error);
    }
}

async function deleteAccount(name) {
    if (!confirm(`Are you sure you want to delete account '${name}'? This action cannot be undone.`)) {
        return;
    }
    
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(name)}`, {
            method: 'DELETE'
        });
        
        showSuccess(`Account ${name} deleted successfully`);
        loadAccounts();
    } catch (error) {
        console.error('Failed to delete account:', error);
    }
}

// Utility Functions
function escapeHTML(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
    if (bytes === 0) return 'Unlimited';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Select Helpers
async function loadAccountsForSelect(selectElement) {
    const currentValue = selectElement.value;
    try {
        const accounts = await fetchAPI('/accounts');
        selectElement.innerHTML = '<option value="">Select account...</option>';
        
        if (accounts && accounts.length > 0) {
            accounts.forEach(account => {
                const option = document.createElement('option');
                option.value = account.name;
                option.textContent = account.name;
                selectElement.appendChild(option);
            });
            
            // Restore previous selection if it still exists
            if (currentValue && Array.from(selectElement.options).some(opt => opt.value === currentValue)) {
                selectElement.value = currentValue;
            } else if (currentValue) {
                // The previously selected account no longer exists
                selectElement.dispatchEvent(new Event('change'));
            }
        }
    } catch (error) {
        console.error('Failed to load accounts for select:', error);
    }
}

// Aliases Management
async function loadEmails(accountName) {
    try {
        const emails = await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/emails`);
        renderEmailsTable(emails, accountName);
    } catch (error) {
        console.error('Failed to load emails:', error);
    }
}

function renderEmailsTable(emails, accountName) {
    elements.aliasesTbody.innerHTML = '';
    
    if (!emails || emails.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="3" class="text-center text-muted">No emails found</td>`;
        elements.aliasesTbody.appendChild(tr);
        return;
    }
    
    emails.forEach(email => {
        const tr = document.createElement('tr');
        
        const isPrimary = email.type === 'primary';
        const badgeClass = isPrimary ? 'badge-primary' : 'badge-alias';
        
        let actionsHtml = '';
        if (!isPrimary) {
            actionsHtml = `
                <button class="btn btn-sm btn-danger btn-delete-alias" data-account="${escapeHTML(accountName)}" data-address="${escapeHTML(email.address)}">
                    Delete
                </button>
            `;
        }
        
        tr.innerHTML = `
            <td><strong>${escapeHTML(email.address)}</strong></td>
            <td><span class="badge ${badgeClass}">${escapeHTML(email.type)}</span></td>
            <td>
                <div class="action-buttons">
                    ${actionsHtml}
                </div>
            </td>
        `;
        
        elements.aliasesTbody.appendChild(tr);
    });
    
    document.querySelectorAll('.btn-delete-alias').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const account = e.target.dataset.account;
            const address = e.target.dataset.address;
            deleteAlias(account, address);
        });
    });
}

async function handleAddAlias(e) {
    e.preventDefault();
    
    const accountName = elements.aliasAccountSelect.value;
    if (!accountName) return;
    
    const address = document.getElementById('alias-address').value;
    
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/emails`, {
            method: 'POST',
            body: JSON.stringify({ address: address, type: 'alias' })
        });
        
        showSuccess(`Alias ${address} added successfully`);
        elements.formAddAlias.reset();
        elements.addAliasContainer.classList.add('hidden');
        elements.btnShowAddAlias.classList.remove('hidden');
        
        loadEmails(accountName);
    } catch (error) {
        console.error('Failed to add alias:', error);
    }
}

async function deleteAlias(accountName, address) {
    if (!confirm(`Are you sure you want to delete alias '${address}'?`)) {
        return;
    }
    
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/emails/${encodeURIComponent(address)}`, {
            method: 'DELETE'
        });
        
        showSuccess(`Alias ${address} deleted successfully`);
        loadEmails(accountName);
    } catch (error) {
        console.error('Failed to delete alias:', error);
    }
}

// Groups Management
async function loadGroups(accountName) {
    try {
        const groups = await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/groups`);
        renderGroupsTable(groups, accountName);
    } catch (error) {
        console.error('Failed to load groups:', error);
    }
}

function renderGroupsTable(groups, accountName) {
    elements.groupsTbody.innerHTML = '';
    
    if (!groups || groups.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="2" class="text-center text-muted">No group memberships found</td>`;
        elements.groupsTbody.appendChild(tr);
        return;
    }
    
    groups.forEach(group => {
        const tr = document.createElement('tr');
        
        tr.innerHTML = `
            <td><strong>${escapeHTML(group)}</strong></td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-danger btn-remove-group" data-account="${escapeHTML(accountName)}" data-group="${escapeHTML(group)}">
                        Remove
                    </button>
                </div>
            </td>
        `;
        
        elements.groupsTbody.appendChild(tr);
    });
    
    document.querySelectorAll('.btn-remove-group').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const account = e.target.dataset.account;
            const group = e.target.dataset.group;
            removeGroup(account, group);
        });
    });
}

async function handleAddGroup(e) {
    e.preventDefault();
    
    const accountName = elements.groupAccountSelect.value;
    if (!accountName) return;
    
    const groupName = document.getElementById('group-name').value;
    
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/groups`, {
            method: 'POST',
            body: JSON.stringify({ member_of: groupName })
        });
        
        showSuccess(`Added to group ${groupName} successfully`);
        elements.formAddGroup.reset();
        elements.addGroupContainer.classList.add('hidden');
        elements.btnShowAddGroup.classList.remove('hidden');
        
        loadGroups(accountName);
    } catch (error) {
        console.error('Failed to add group:', error);
    }
}

async function removeGroup(accountName, group) {
    if (!confirm(`Are you sure you want to remove membership from group '${group}'?`)) {
        return;
    }
    
    try {
        await fetchAPI(`/accounts/${encodeURIComponent(accountName)}/groups/${encodeURIComponent(group)}`, {
            method: 'DELETE'
        });
        
        showSuccess(`Removed from group ${group} successfully`);
        loadGroups(accountName);
    } catch (error) {
        console.error('Failed to remove group:', error);
    }
}

// Start the app
document.addEventListener('DOMContentLoaded', init);
