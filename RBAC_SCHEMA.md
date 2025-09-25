# RBAC Schema

Обновлённая схема RBAC для Custom Auth. Ниже описаны сущности, связи и основные потоки аутентификации/авторизации.

## Database Schema

### 1. Users

#### `accounts_user`
- UUID‑PK, soft delete (`is_active`)
- Поля:
  - `id`: UUID (Primary Key)
  - `email`: Unique email address
  - `first_name`: User's first name
  - `last_name`: User's last name
  - `password`: Hashed password
  - `is_active`: Boolean flag for soft delete
  - `created_at`: Account creation timestamp
  - `updated_at`: Last modification timestamp

### 2. Permissions & Roles

#### `authorization_permission`
- Справочник действий/прав
- Поля:
  - `id`: Auto-increment primary key
  - `code`: Unique permission code (e.g., 'read_users', 'create_roles')
  - `description`: Detailed permission description
  - `element`: Domain area for the permission
  - `created_at`: Creation timestamp

#### `authorization_role`
- Группировка прав
- Поля:
  - `id`: Auto-increment primary key
  - `name`: Role name (e.g., 'admin', 'manager', 'viewer')
  - `description`: Role description
  - `created_at`: Creation timestamp

### 3. Relationships

#### `authorization_userrole`
- Связь пользователь ↔ роль
- Поля:
  - `id`: Auto-increment primary key
  - `user_id`: Foreign key to accounts_user
  - `role_id`: Foreign key to authorization_role
  - `created_at`: Assignment timestamp

#### `authorization_rolepermission`
- Связь роль ↔ право
- Поля:
  - `id`: Auto-increment primary key
  - `role_id`: Foreign key to authorization_role
  - `permission_id`: Foreign key to authorization_permission
  - `created_at`: Assignment timestamp

### 4. Resources

#### `resources_resource`
- Бизнес‑объекты с требованием права
- Поля:
  - `id`: Auto-increment primary key
  - `name`: Resource name
  - `description`: Resource description
  - `permission_required`: Required permission code for access
  - `created_at`: Creation timestamp

## Permission catalog

### Примеры прав

#### Document Management
- `read_documents`: Read document content
- `create_documents`: Create new documents
- `update_documents`: Modify existing documents
- `delete_documents`: Remove documents

#### User Management
- `read_users`: View user information
- `create_users`: Create new user accounts
- `update_users`: Modify user profiles
- `delete_users`: Deactivate user accounts
- `manage_users`: Full user management access

#### Role Management
- `read_roles`: View role information
- `create_roles`: Create new roles
- `update_roles`: Modify role definitions
- `delete_roles`: Remove roles
- `manage_roles`: Full role management access

#### Permission Management
- `read_permissions`: View permission information
- `create_permissions`: Create new permissions
- `update_permissions`: Modify permission definitions
- `delete_permissions`: Remove permissions
- `manage_permissions`: Full permission management access

#### Resource Management
- `read_resources`: View resource information
- `create_resources`: Create new resources
- `update_resources`: Modify existing resources
- `delete_resources`: Remove resources
- `manage_resources`: Full resource management access

#### Special Access
- `read_secrets`: Access to secret/confidential information
- `admin_access`: Administrative system access
- `view_analytics`: Access to analytics and reports
- `manage_settings`: System configuration access

## Role presets (demo)

### 1. Admin Role
- **Description**: Full system access
- **Permissions**: All permissions
- **Use Case**: System administrators

### 2. Manager Role
- **Description**: Management-level access
- **Permissions**: User management, resource management, analytics
- **Use Case**: Department managers, team leads

### 3. Editor Role
- **Description**: Content creation and editing
- **Permissions**: Document management, resource updates
- **Use Case**: Content creators, editors

### 4. Viewer Role
- **Description**: Read-only access
- **Permissions**: Read permissions for documents, users, resources
- **Use Case**: Regular users, observers

### 5. Secret Reader Role
- **Description**: Access to confidential information
- **Permissions**: Read secrets, special documents
- **Use Case**: Security personnel, auditors

### 6. Analyst Role
- **Description**: Analytics and reporting access
- **Permissions**: View analytics, read reports
- **Use Case**: Data analysts, business intelligence

## Потоки

### Authentication (JWT)
1. User provides email/password
2. System validates credentials
3. JWT access token issued (15 minutes)
4. JWT refresh token issued (7 days)

### Authorization
1. Request includes JWT token
2. System validates token and identifies user
3. System retrieves user's roles and permissions
4. System checks if user has required permission
5. Access granted (200) or denied (403)

### Error handling
- **401 Unauthorized**: Invalid or missing authentication token
- **403 Forbidden**: Valid user but insufficient permissions
- **404 Not Found**: Resource doesn't exist or user can't see it

## Demo data

### Demo Users
- `admin@example.com` / `admin123` - Admin role
- `manager@example.com` / `manager123` - Manager role
- `editor@example.com` / `editor123` - Editor role
- `viewer@example.com` / `viewer123` - Viewer role
- `secret@example.com` / `secret123` - Secret Reader role
- `analyst@example.com` / `analyst123` - Analyst role

### Demo Resources
- Public Document (requires `read_documents`)
- Secret Document (requires `read_secrets`)
- Admin Only Document (requires `admin_access`)
- Manager Resource (requires `read_resources`)
- Analytics Report (requires `view_analytics`)
- User Management Guide (requires `read_users`)

## API Endpoints

### Authentication
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/refresh/` - Token refresh
- `GET /api/auth/profile/` - User profile

### User Management (Admin only)
- `GET /api/accounts/users/` - List users
- `POST /api/accounts/users/` - Create user
- `GET /api/accounts/users/{id}/` - Get user details
- `PUT /api/accounts/users/{id}/` - Update user
- `DELETE /api/accounts/users/{id}/` - Deactivate user

### Role Management (Admin only)
- `GET /api/authorization/roles/` - List roles
- `POST /api/authorization/roles/` - Create role
- `GET /api/authorization/roles/{id}/` - Get role details
- `PUT /api/authorization/roles/{id}/` - Update role
- `DELETE /api/authorization/roles/{id}/` - Delete role

### Permission Management (Admin only)
- `GET /api/authorization/permissions/` - List permissions
- `POST /api/authorization/permissions/` - Create permission
- `GET /api/authorization/permissions/{id}/` - Get permission details
- `PUT /api/authorization/permissions/{id}/` - Update permission
- `DELETE /api/authorization/permissions/{id}/` - Delete permission

### Resource Management
- `GET /api/resources/resources/` - List accessible resources
- `POST /api/resources/resources/` - Create resource (requires permission)
- `GET /api/resources/resources/{id}/` - Get resource details
- `PUT /api/resources/resources/{id}/` - Update resource (requires permission)
- `DELETE /api/resources/resources/{id}/` - Delete resource (requires permission)
- `GET /api/resources/test-access/{id}/` - Test resource access

## Web Interface

### Authentication Pages

#### **Login Page** (`/login/`)
- **Modern UI** with responsive design
- **Demo user buttons** for easy testing
- **Real-time validation** and error handling
- **JWT token management** with localStorage
- **Automatic redirect** to dashboard after login

#### **Registration Page** (`/register/`)
- **Comprehensive form** with validation
- **Password strength requirements** with real-time feedback
- **Field-specific error handling** for better UX
- **Automatic redirect** to login after registration

#### **Dashboard Page** (`/dashboard/`)
- **Personalized user information** display
- **Role and permission visualization** with badges
- **Quick action buttons** for system testing
- **Navigation links** to demo interface and API docs
- **Secure logout** functionality

### Demo Interface (`/detailed-demo/`)

#### **Authentication Tab**
- **Login/logout** functionality
- **User information** display
- **Role and permission** overview

#### **Dashboard Tab**
- **System statistics** (users, roles, permissions)
- **Resource listing** with access control
- **Role and permission** management

#### **Administration Tab**
- **User management** (admin only)
- **Role management** (create, edit, delete)
- **Permission management** (assign, revoke)

#### **Testing Tab**
- **Resource access testing** - all resources with visual indicators
- **Permission testing** - individual permission checks
- **Visual feedback** - ✓ allowed, ✗ denied

## Security Considerations

1. **JWT Token Security**: Short-lived access tokens, secure refresh mechanism
2. **Password Hashing**: Django's built-in PBKDF2 with salt
3. **Soft Delete**: User data preserved for audit trails
4. **Permission Granularity**: Fine-grained permission system
5. **Role Hierarchy**: Logical grouping of permissions
6. **Input Validation**: Comprehensive validation on all inputs
7. **Error Handling**: Secure error messages without information leakage
8. **Web Security**: CSRF protection, XSS prevention, secure headers
9. **Client-side Security**: Token validation, automatic logout on expiry
10. **UI Security**: Visual indicators for access status, secure form handling
