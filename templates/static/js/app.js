// Global variables
let currentUser = null;
let authToken = null;
let resources = [];
let roles = [];
let permissions = [];

// API Base URL
const API_BASE = '/api';

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Check if user is already logged in
    const token = localStorage.getItem('authToken');
    if (token) {
        authToken = token;
        // Load user profile and data
        loadUserProfile();
        loadResources();
        loadRoles();
        loadPermissions();
    }
    
    // Setup event listeners
    setupEventListeners();
}

function setupEventListeners() {
    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Registration form
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
    
    // Tab switching
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            switchTab(this.dataset.tab);
        });
    });
    
    // Logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    
    // Modal close events
    const closeButtons = document.querySelectorAll('.close');
    closeButtons.forEach(btn => {
        btn.addEventListener('click', closeModal);
    });
    
    // Click outside modal to close
    window.addEventListener('click', function(event) {
        const modal = document.getElementById('testModal');
        if (event.target === modal) {
            closeModal();
        }
    });
}

// Authentication functions
async function handleLogin(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        email: formData.get('email'),
        password: formData.get('password')
    };
    
    try {
        const response = await fetch(`${API_BASE}/auth/login/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            authToken = result.access_token;
            localStorage.setItem('authToken', authToken);
            showAlert('Успешный вход в систему!', 'success');
            // Reload the page to initialize with new token
            window.location.reload();
        } else {
            showAlert(result.detail || 'Ошибка входа', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = {
        email: formData.get('email'),
        password: formData.get('password'),
        first_name: formData.get('first_name'),
        last_name: formData.get('last_name')
    };
    
    try {
        const response = await fetch(`${API_BASE}/auth/register/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showAlert('Регистрация успешна! Теперь войдите в систему.', 'success');
            e.target.reset();
        } else {
            showAlert(result.detail || 'Ошибка регистрации', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

async function loadUserProfile() {
    if (!authToken) {
        currentUser = null;
        updateUserDisplay();
        return;
    }
    
    try {
        console.log('Loading user profile...');
        const response = await fetch(`${API_BASE}/auth/profile/`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        console.log('Profile response status:', response.status);
        if (response.ok) {
            currentUser = await response.json();
            console.log('User profile loaded:', currentUser);
            updateUserDisplay();
        } else {
            console.error('Profile load failed:', response.status);
            handleLogout();
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        handleLogout();
    }
}

function handleLogout() {
    if (authToken) {
        fetch(`${API_BASE}/auth/logout/`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            }
        }).catch(() => {});
    }
    fetch('/api/web/logout/', { method: 'POST' }).catch(() => {});
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    showAlert('Вы вышли из системы', 'info');
    updateUserDisplay();
    switchTab('auth');
    setTimeout(() => {
        window.location.href = '/login/';
    }, 300);
}

// Data loading functions
async function loadResources() {
    try {
        console.log('Loading resources...');
        const headers = {};
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        const response = await fetch(`${API_BASE}/resources/resources/`, { headers });
        console.log('Resources response status:', response.status);
        if (response.ok) {
            resources = await response.json();
            console.log('Resources loaded:', resources);
            updateResourcesDisplay();
            updateTestResourcesDisplay();
            updateStats();
        } else {
            if (response.status === 401) {
                showAlert('Не авторизован (401). Пожалуйста, войдите заново.', 'warning');
                handleLogout();
            } else if (response.status === 403) {
                showAlert('Доступ запрещен (403) к списку ресурсов.', 'danger');
            } else {
                const errorText = await response.text();
                console.error('Error loading resources:', response.status, errorText);
                showAlert(`Ошибка загрузки ресурсов (HTTP ${response.status})`, 'danger');
            }
        }
    } catch (error) {
        console.error('Error loading resources:', error);
        showAlert('Ошибка соединения при загрузке ресурсов', 'danger');
    }
}

// Load all resources for testing (regardless of permissions)
async function loadAllResourcesForTesting() {
    console.log('Loading all resources for testing...');
    
    // Define all available resources for testing (based on our seed data)
    const allTestResources = [
        {
            id: 1,
            name: 'Public Document',
            description: 'A public document that anyone with read access can view',
            permission_required: 'read_documents',
            created_at: '2025-09-21T19:13:15.406568Z'
        },
        {
            id: 2,
            name: 'Secret Document',
            description: 'A secret document requiring special permission',
            permission_required: 'read_secrets',
            created_at: '2025-09-21T19:13:15.411103Z'
        },
        {
            id: 3,
            name: 'Admin Only Document',
            description: 'A document only admins can access',
            permission_required: 'admin_access',
            created_at: '2025-09-21T19:13:15.415275Z'
        },
        {
            id: 4,
            name: 'Manager Resource',
            description: 'A resource that managers can access',
            permission_required: 'read_resources',
            created_at: '2025-09-21T19:13:15.420515Z'
        },
        {
            id: 5,
            name: 'Analytics Report',
            description: 'A report that analysts can view',
            permission_required: 'view_analytics',
            created_at: '2025-09-21T19:13:15.425254Z'
        },
        {
            id: 6,
            name: 'User Management Guide',
            description: 'A guide for user management operations',
            permission_required: 'read_users',
            created_at: '2025-09-21T19:13:15.429022Z'
        }
    ];
    
    console.log('All test resources loaded:', allTestResources);
    updateTestResourcesDisplay(allTestResources);
}

async function loadRoles() {
    try {
        console.log('Loading roles...');
        const headers = {};
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        const response = await fetch(`${API_BASE}/authorization/roles/`, { headers });
        console.log('Roles response status:', response.status);
        if (response.ok) {
            roles = await response.json();
            console.log('Roles loaded:', roles);
            updateRolesDisplay();
            updateStats();
        } else {
            if (response.status === 401) {
                showAlert('Не авторизован (401). Пожалуйста, войдите заново.', 'warning');
                handleLogout();
            } else if (response.status === 403) {
                showAlert('Доступ запрещен (403) к ролям.', 'danger');
            } else {
                const errorText = await response.text();
                console.error('Error loading roles:', response.status, errorText);
                showAlert(`Ошибка загрузки ролей (HTTP ${response.status})`, 'danger');
            }
        }
    } catch (error) {
        console.error('Error loading roles:', error);
        showAlert('Ошибка соединения при загрузке ролей', 'danger');
    }
}

async function loadPermissions() {
    try {
        console.log('Loading permissions...');
        const headers = {};
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        const response = await fetch(`${API_BASE}/authorization/permissions/`, { headers });
        console.log('Permissions response status:', response.status);
        if (response.ok) {
            permissions = await response.json();
            console.log('Permissions loaded:', permissions);
            updatePermissionsDisplay();
            updateStats();
        } else {
            if (response.status === 401) {
                showAlert('Не авторизован (401). Пожалуйста, войдите заново.', 'warning');
                handleLogout();
            } else if (response.status === 403) {
                showAlert('Доступ запрещен (403) к правам.', 'danger');
            } else {
                const errorText = await response.text();
                console.error('Error loading permissions:', response.status, errorText);
                showAlert(`Ошибка загрузки прав (HTTP ${response.status})`, 'danger');
            }
        }
    } catch (error) {
        console.error('Error loading permissions:', error);
        showAlert('Ошибка соединения при загрузке прав', 'danger');
    }
}

// Display update functions
function updateUserDisplay() {
    const userCard = document.getElementById('userCard');
    if (!userCard) return;
    
    if (currentUser) {
        console.log('Updating user display with:', currentUser);
        userCard.innerHTML = `
            <h4>Добро пожаловать, ${currentUser.first_name || ''} ${currentUser.last_name || ''}!</h4>
            <p><strong>Email:</strong> ${currentUser.email}</p>
            <p><strong>Роли:</strong> ${currentUser.roles ? currentUser.roles.map(role => `<span class="badge badge-primary">${role}</span>`).join(' ') : 'Нет ролей'}</p>
            <p><strong>Права:</strong> ${currentUser.permissions ? currentUser.permissions.map(perm => `<span class="badge badge-success">${perm}</span>`).join(' ') : 'Нет прав'}</p>
            <button class="btn btn-danger" onclick="handleLogout()">Выйти</button>
        `;
        userCard.style.display = 'block';
        
        // Update admin section visibility
        updateAdminSectionVisibility();
    } else {
        userCard.style.display = 'none';
    }
}

function updateAdminSectionVisibility() {
    if (!currentUser) return;
    
    const hasAdminAccess = currentUser.permissions && 
        (currentUser.permissions.includes('admin_access') || currentUser.permissions.includes('manage_roles'));
    
    const addRoleSection = document.getElementById('addRoleSection');
    if (addRoleSection) {
        addRoleSection.style.display = hasAdminAccess ? 'block' : 'none';
    }
    const addPermissionSection = document.getElementById('addPermissionSection');
    if (addPermissionSection) {
        addPermissionSection.style.display = hasAdminAccess ? 'block' : 'none';
    }
    
    const adminAccessMessage = document.getElementById('adminAccessMessage');
    if (adminAccessMessage) {
        adminAccessMessage.style.display = hasAdminAccess ? 'none' : 'block';
    }
    
    // Show admin access message if no permissions
    if (!hasAdminAccess) {
        const adminTab = document.querySelector('[data-tab="admin"]');
        if (adminTab) {
            adminTab.innerHTML = 'Администрирование <span style="color: #dc3545;">(Нет доступа)</span>';
        }
    }
}

function updateResourcesDisplay() {
    const resourcesContainer = document.getElementById('resourcesList');
    if (!resourcesContainer) return;
    
    if (!resources || resources.length === 0) {
        resourcesContainer.innerHTML = '<p>Нет доступных ресурсов.</p>';
        return;
    }
    
    resourcesContainer.innerHTML = resources.map(resource => `
        <div class="resource-item">
            <h5>${resource.name}</h5>
            <p>${resource.description}</p>
            <p><strong>Требуемое право:</strong> <span class="badge badge-warning">${resource.permission_required}</span></p>
            <p><strong>Создано:</strong> ${new Date(resource.created_at).toLocaleString()}</p>
        </div>
    `).join('');
}

function updateTestResourcesDisplay(resourcesToShow = null) {
    const testResourcesContainer = document.getElementById('testResourcesList');
    if (!testResourcesContainer) return;
    
    const resourcesToDisplay = resourcesToShow || resources;
    
    if (!resourcesToDisplay || resourcesToDisplay.length === 0) {
        testResourcesContainer.innerHTML = '<p>Нет доступных ресурсов для тестирования.</p>';
        return;
    }
    
    // Check if user has permissions for each resource
    const hasPermission = (permissionRequired) => {
        if (!currentUser || !currentUser.permissions) return false;
        return currentUser.permissions.includes(permissionRequired);
    };
    
    testResourcesContainer.innerHTML = resourcesToDisplay.map(resource => {
        const userHasPermission = hasPermission(resource.permission_required);
        const accessStatus = userHasPermission ? 'success' : 'danger';
        const statusText = userHasPermission ? 'Доступ разрешен' : 'Доступ запрещен';
        const statusIcon = userHasPermission ? '✓' : '✗';
        
        return `
            <div class="resource-item">
                <div class="resource-header">
                    <h5>${resource.name}</h5>
                    <span class="badge badge-${accessStatus}">${statusIcon} ${statusText}</span>
                </div>
                <p>${resource.description}</p>
                <p><strong>Требуемое право:</strong> <span class="badge badge-warning">${resource.permission_required}</span></p>
                <button class="btn btn-primary" onclick="testResourceAccess(${resource.id})">
                    Test Access
                </button>
            </div>
        `;
    }).join('');
}

function updateStats() {
    const totalUsers = document.getElementById('totalUsers');
    const totalRoles = document.getElementById('totalRoles');
    const totalPermissions = document.getElementById('totalPermissions');
    const totalResources = document.getElementById('totalResources');
    
    if (totalUsers) totalUsers.textContent = currentUser ? '1' : '0';
    if (totalRoles) totalRoles.textContent = roles.length;
    if (totalPermissions) totalPermissions.textContent = permissions.length;
    if (totalResources) totalResources.textContent = resources.length;
}

function updateRolesDisplay() {
    const rolesContainer = document.getElementById('rolesList');
    if (!rolesContainer) return;
    
    // Check if user has admin permissions
    const hasAdminAccess = currentUser && currentUser.permissions && 
        (currentUser.permissions.includes('admin_access') || currentUser.permissions.includes('manage_roles'));
    
    rolesContainer.innerHTML = `
        <table class="table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Название</th>
                    <th>Описание</th>
                    <th>Права</th>
                    ${hasAdminAccess ? '<th>Действия</th>' : ''}
                </tr>
            </thead>
            <tbody>
                ${roles.map(role => `
                    <tr>
                        <td>${role.id}</td>
                        <td class="editable" data-field="name" data-id="${role.id}">${role.name}</td>
                        <td class="editable" data-field="description" data-id="${role.id}">${role.description}</td>
                        <td>${role.permissions ? role.permissions.map(p => `<span class="badge badge-primary">${p.code}</span>`).join(' ') : 'Нет'}</td>
                        ${hasAdminAccess ? `
                            <td>
                                <button class="btn btn-warning btn-sm" onclick="editRole(${role.id})">Редактировать</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteRole(${role.id})">Удалить</button>
                            </td>
                        ` : ''}
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

function updatePermissionsDisplay() {
    const permissionsContainer = document.getElementById('permissionsList');
    if (!permissionsContainer) return;
    
    const hasAdminAccess = currentUser && currentUser.permissions && 
        (currentUser.permissions.includes('admin_access') || currentUser.permissions.includes('manage_roles'));
    
    permissionsContainer.innerHTML = `
        <table class="table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Код</th>
                    <th>Элемент</th>
                    <th>Описание</th>
                    ${hasAdminAccess ? '<th>Действия</th>' : ''}
                </tr>
            </thead>
            <tbody>
                ${permissions.map(permission => `
                    <tr>
                        <td>${permission.id}</td>
                        <td class="editable" data-field="code" data-id="${permission.id}">${permission.code}</td>
                        <td class="editable" data-field="element" data-id="${permission.id}">${permission.element}</td>
                        <td class="editable" data-field="description" data-id="${permission.id}">${permission.description}</td>
                        ${hasAdminAccess ? `
                        <td>
                            <button class="btn btn-warning btn-sm" onclick="editPermission(${permission.id})">Edit</button>
                            <button class="btn btn-danger btn-sm" onclick="deletePermission(${permission.id})">Delete</button>
                        </td>` : ''}
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Tab switching
function switchTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));
    
    // Remove active class from all tabs
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => tab.classList.remove('active'));
    
    // Show selected tab content
    const selectedContent = document.getElementById(tabName);
    if (selectedContent) {
        selectedContent.classList.add('active');
    }
    
    // Add active class to selected tab
    const selectedTab = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }
    
    // Load all resources for testing when testing tab is selected
    if (tabName === 'testing') {
        loadAllResourcesForTesting();
    }
}

// Test functions
async function testResourceAccess(resourceId) {
    if (!authToken) {
        showAlert('Необходимо войти в систему', 'warning');
        return;
    }
    
    showModal('Тестирование доступа к ресурсу', 'loading');
    
    try {
        const response = await fetch(`${API_BASE}/resources/test-access/${resourceId}/`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            showSuccessModal('Доступ разрешен! (200)', result);
        } else {
            let errorData;
            try {
                errorData = await response.json();
            } catch (jsonError) {
                errorData = { error: `HTTP ${response.status}: ${response.statusText}` };
            }
            if (response.status === 401) {
                showErrorModal('Не авторизован (401)', errorData);
                handleLogout();
            } else if (response.status === 403) {
                showErrorModal('Доступ запрещен (403)', errorData);
            } else {
                showErrorModal(`Ошибка (HTTP ${response.status})`, errorData);
            }
        }
    } catch (error) {
        showErrorModal('Ошибка соединения', { error: error.message });
    }
}

async function testPermission(permissionCode) {
    if (!authToken) {
        showAlert('Необходимо войти в систему', 'warning');
        return;
    }
    
    showModal('Тестирование права', 'loading');
    
    try {
        const response = await fetch(`${API_BASE}/authorization/test-permission/`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ permission: permissionCode })
        });
        
        if (response.ok) {
            const result = await response.json();
            showSuccessModal('Право подтверждено! (200)', result);
        } else {
            let errorData;
            try {
                errorData = await response.json();
            } catch (jsonError) {
                errorData = { error: `HTTP ${response.status}: ${response.statusText}` };
            }
            if (response.status === 401) {
                showErrorModal('Не авторизован (401)', errorData);
                handleLogout();
            } else if (response.status === 403) {
                showErrorModal('Недостаточно прав (403)', errorData);
            } else {
                showErrorModal(`Ошибка (HTTP ${response.status})`, errorData);
            }
        }
    } catch (error) {
        showErrorModal('Ошибка соединения', { error: error.message });
    }
}

// Modal functions
function showModal(title, type) {
    const modal = document.getElementById('testModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    
    modalTitle.textContent = title;
    
    if (type === 'loading') {
        modalBody.innerHTML = `
            <div class="loading-modal">
                <div class="loading-spinner"></div>
                <p>Проверка доступа...</p>
            </div>
        `;
    }
    
    modal.style.display = 'block';
}

function showSuccessModal(title, data) {
    const modal = document.getElementById('testModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    
    modalTitle.textContent = title;
    modalBody.innerHTML = `
        <div class="text-center">
            <div class="success-icon">✓</div>
            <h4>Успешно!</h4>
            <p>Операция выполнена успешно.</p>
            <div class="response-details">
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        </div>
    `;
    
    modal.style.display = 'block';
}

function showErrorModal(title, data) {
    const modal = document.getElementById('testModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    
    modalTitle.textContent = title;
    modalBody.innerHTML = `
        <div class="text-center">
            <div class="error-icon">✗</div>
            <h4>Ошибка!</h4>
            <p>Операция не выполнена.</p>
            <div class="response-details">
                <pre>${JSON.stringify(data, null, 2)}</pre>
            </div>
        </div>
    `;
    
    modal.style.display = 'block';
}

function closeModal() {
    const modal = document.getElementById('testModal');
    modal.style.display = 'none';
}

// Edit functions
function editRole(roleId) {
    // Check admin permissions
    if (!currentUser || !currentUser.permissions || 
        (!currentUser.permissions.includes('admin_access') && !currentUser.permissions.includes('manage_roles'))) {
        showAlert('У вас нет прав для редактирования ролей', 'danger');
        return;
    }
    
    const role = roles.find(r => r.id === roleId);
    if (!role) return;
    
    // Create edit form
    const editForm = document.createElement('div');
    editForm.className = 'edit-form';
    editForm.innerHTML = `
        <h4>Редактирование роли</h4>
        <form onsubmit="saveRole(${roleId}, event)">
            <div class="form-group">
                <label>Название:</label>
                <input type="text" name="name" value="${role.name}" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Описание:</label>
                <textarea name="description" class="form-control" rows="3">${role.description}</textarea>
            </div>
            <div class="form-group">
                <label>Права:</label>
                <div class="checkbox-list">
                    ${permissions.map(perm => {
                        const checked = role.permissions && role.permissions.some(p => p.id === perm.id) ? 'checked' : '';
                        return `<label class="checkbox-item">
                            <input type="checkbox" name="permission_ids" value="${perm.id}" ${checked}> ${perm.code} - ${perm.description}
                        </label>`;
                    }).join('')}
                </div>
            </div>
            <div class="form-group">
                <button type="submit" class="btn btn-success">Сохранить</button>
                <button type="button" class="btn btn-secondary" onclick="cancelEdit()">Отмена</button>
            </div>
        </form>
    `;
    
    // Replace role row with edit form
    const roleRow = document.querySelector(`tr:has(td[data-id="${roleId}"])`);
    if (roleRow) {
        roleRow.innerHTML = `<td colspan="5">${editForm.outerHTML}</td>`;
    }
}

function editPermission(permissionId) {
    const permission = permissions.find(p => p.id === permissionId);
    if (!permission) return;
    
    // Create edit form
    const editForm = document.createElement('div');
    editForm.className = 'edit-form';
    editForm.innerHTML = `
        <h4>Редактирование права</h4>
        <form onsubmit="savePermission(${permissionId}, event)">
            <div class="form-group">
                <label>Код:</label>
                <input type="text" name="code" value="${permission.code}" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Элемент:</label>
                <input type="text" name="element" value="${permission.element}" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Описание:</label>
                <textarea name="description" class="form-control" rows="3">${permission.description}</textarea>
            </div>
            <div class="form-group">
                <button type="submit" class="btn btn-success">Сохранить</button>
                <button type="button" class="btn btn-secondary" onclick="cancelEdit()">Отмена</button>
            </div>
        </form>
    `;
    
    // Replace permission row with edit form
    const permissionRow = document.querySelector(`tr:has(td[data-id="${permissionId}"])`);
    if (permissionRow) {
        permissionRow.innerHTML = `<td colspan="5">${editForm.outerHTML}</td>`;
    }
}

async function saveRole(roleId, event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const permissionIds = Array.from(document.querySelectorAll('input[name="permission_ids"]:checked')).map(cb => parseInt(cb.value));
    const data = {
        name: formData.get('name'),
        description: formData.get('description'),
        permission_ids: permissionIds
    };
    
    try {
        const response = await fetch(`${API_BASE}/authorization/roles/${roleId}/`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showAlert('Роль обновлена!', 'success');
            loadRoles();
        } else {
            const error = await response.json();
            showAlert(error.detail || 'Ошибка обновления роли', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

async function savePermission(permissionId, event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = {
        code: formData.get('code'),
        element: formData.get('element'),
        description: formData.get('description')
    };
    
    try {
        const response = await fetch(`${API_BASE}/authorization/permissions/${permissionId}/`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showAlert('Право обновлено!', 'success');
            loadPermissions();
        } else {
            const error = await response.json();
            showAlert(error.detail || 'Ошибка обновления права', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

function cancelEdit() {
    loadRoles();
    loadPermissions();
}

async function deleteRole(roleId) {
    // Check admin permissions
    if (!currentUser || !currentUser.permissions || 
        (!currentUser.permissions.includes('admin_access') && !currentUser.permissions.includes('manage_roles'))) {
        showAlert('У вас нет прав для удаления ролей', 'danger');
        return;
    }
    
    if (!confirm('Вы уверены, что хотите удалить эту роль?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/authorization/roles/${roleId}/`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            showAlert('Роль удалена!', 'success');
            loadRoles();
        } else {
            showAlert('Ошибка удаления роли', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

async function deletePermission(permissionId) {
    if (!confirm('Вы уверены, что хотите удалить это право?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/authorization/permissions/${permissionId}/`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (response.ok) {
            showAlert('Право удалено!', 'success');
            loadPermissions();
        } else {
            showAlert('Ошибка удаления права', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

// Add new item functions
function showAddRoleForm() {
    // Check admin permissions
    if (!currentUser || !currentUser.permissions || 
        (!currentUser.permissions.includes('admin_access') && !currentUser.permissions.includes('manage_roles'))) {
        showAlert('У вас нет прав для управления ролями', 'danger');
        return;
    }
    
    const rolesContainer = document.getElementById('rolesList');
    if (!rolesContainer) return;
    
    const addForm = document.createElement('div');
    addForm.className = 'edit-form';
    addForm.innerHTML = `
        <h4>Добавление новой роли</h4>
        <form onsubmit="addRole(event)">
            <div class="form-group">
                <label>Название:</label>
                <input type="text" name="name" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Описание:</label>
                <textarea name="description" class="form-control" rows="3"></textarea>
            </div>
            <div class="form-group">
                <label>Права:</label>
                <div class="checkbox-list">
                    ${permissions.map(perm => 
                        `<label class=\"checkbox-item\"><input type=\"checkbox\" name=\"permission_ids\" value=\"${perm.id}\"> ${perm.code} - ${perm.description}</label>`
                    ).join('')}
                </div>
            </div>
            <div class="form-group">
                <button type="submit" class="btn btn-success">Добавить</button>
                <button type="button" class="btn btn-secondary" onclick="cancelAdd()">Отмена</button>
            </div>
        </form>
    `;
    
    rolesContainer.innerHTML = addForm.outerHTML + rolesContainer.innerHTML;
}

function showAddPermissionForm() {
    const permissionsContainer = document.getElementById('permissionsList');
    if (!permissionsContainer) return;
    
    const addForm = document.createElement('div');
    addForm.className = 'edit-form';
    addForm.innerHTML = `
        <h4>Добавление нового права</h4>
        <form onsubmit="addPermission(event)">
            <div class="form-group">
                <label>Код:</label>
                <input type="text" name="code" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Элемент:</label>
                <input type="text" name="element" class="form-control" required>
            </div>
            <div class="form-group">
                <label>Описание:</label>
                <textarea name="description" class="form-control" rows="3"></textarea>
            </div>
            <div class="form-group">
                <button type="submit" class="btn btn-success">Добавить</button>
                <button type="button" class="btn btn-secondary" onclick="cancelAdd()">Отмена</button>
            </div>
        </form>
    `;
    
    permissionsContainer.innerHTML = addForm.outerHTML + permissionsContainer.innerHTML;
}

async function addRole(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const permissionIds = Array.from(document.querySelectorAll('input[name="permission_ids"]:checked')).map(cb => parseInt(cb.value));
    const data = {
        name: formData.get('name'),
        description: formData.get('description'),
        permission_ids: permissionIds
    };
    
    try {
        const response = await fetch(`${API_BASE}/authorization/roles/`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showAlert('Роль добавлена!', 'success');
            loadRoles();
        } else {
            const error = await response.json();
            showAlert(error.detail || 'Ошибка добавления роли', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

async function addPermission(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = {
        code: formData.get('code'),
        element: formData.get('element'),
        description: formData.get('description')
    };
    
    try {
        const response = await fetch(`${API_BASE}/authorization/permissions/`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            showAlert('Право добавлено!', 'success');
            loadPermissions();
        } else {
            const error = await response.json();
            showAlert(error.detail || 'Ошибка добавления права', 'danger');
        }
    } catch (error) {
        showAlert('Ошибка соединения', 'danger');
    }
}

function cancelAdd() {
    loadRoles();
    loadPermissions();
}

// Utility functions
function showAlert(message, type) {
    const alertContainer = document.getElementById('alertContainer');
    if (!alertContainer) return;
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    
    alertContainer.appendChild(alert);
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}


