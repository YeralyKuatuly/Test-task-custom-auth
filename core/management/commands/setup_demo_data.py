from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from authorization.models import Role, Permission, UserRole
from resources.models import Resource

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up demo data for the authentication system'

    def handle(self, *args, **options):
        self.stdout.write('Setting up demo data...')

        # Create permissions
        permissions_data = [
            # Document permissions
            {'code': 'read_documents', 'description': 'Read documents',
             'element': 'documents'},
            {'code': 'write_documents', 'description': 'Write documents',
             'element': 'documents'},
            {'code': 'delete_documents', 'description': 'Delete documents',
             'element': 'documents'},
            {'code': 'create_documents', 'description': 'Create documents',
             'element': 'documents'},
            {'code': 'update_documents', 'description': 'Update documents',
             'element': 'documents'},

            # User management permissions
            {'code': 'read_users', 'description': 'Read user information',
             'element': 'users'},
            {'code': 'create_users', 'description': 'Create new users',
             'element': 'users'},
            {'code': 'update_users', 'description': 'Update user information',
             'element': 'users'},
            {'code': 'delete_users', 'description': 'Delete users',
             'element': 'users'},
            {'code': 'manage_users', 'description': 'Full user management access',
             'element': 'users'},

            # Role management permissions
            {'code': 'read_roles', 'description': 'Read role information',
             'element': 'roles'},
            {'code': 'create_roles', 'description': 'Create new roles',
             'element': 'roles'},
            {'code': 'update_roles', 'description': 'Update role information',
             'element': 'roles'},
            {'code': 'delete_roles', 'description': 'Delete roles',
             'element': 'roles'},
            {'code': 'manage_roles', 'description': 'Full role management access',
             'element': 'roles'},

            # Permission management permissions
            {'code': 'read_permissions', 'description': 'Read permission information',
             'element': 'permissions'},
            {'code': 'create_permissions', 'description': 'Create new permissions',
             'element': 'permissions'},
            {'code': 'update_permissions', 'description': 'Update permission information',
             'element': 'permissions'},
            {'code': 'delete_permissions', 'description': 'Delete permissions',
             'element': 'permissions'},
            {'code': 'manage_permissions', 'description': 'Full permission management access',
             'element': 'permissions'},

            # Resource management permissions
            {'code': 'read_resources', 'description': 'Read resource information',
             'element': 'resources'},
            {'code': 'create_resources', 'description': 'Create new resources',
             'element': 'resources'},
            {'code': 'update_resources', 'description': 'Update resource information',
             'element': 'resources'},
            {'code': 'delete_resources', 'description': 'Delete resources',
             'element': 'resources'},
            {'code': 'manage_resources', 'description': 'Full resource management access',
             'element': 'resources'},

            # Special access permissions
            {'code': 'read_secrets', 'description': 'Read secret information',
             'element': 'secrets'},
            {'code': 'admin_access', 'description': 'Full admin access',
             'element': 'admin'},
            {'code': 'view_analytics', 'description': 'View system analytics and statistics',
             'element': 'analytics'},
            {'code': 'manage_settings', 'description': 'Manage system settings',
             'element': 'settings'},
        ]

        permissions = {}
        for perm_data in permissions_data:
            permission, created = Permission.objects.get_or_create(
                code=perm_data['code'],
                defaults=perm_data
            )
            permissions[perm_data['code']] = permission
            if created:
                self.stdout.write(f'Created permission: {permission.code}')

        # Create roles
        roles_data = [
            {
                'name': 'admin',
                'description': 'System administrator with full access to all features',
                'permissions': [
                    # Admin access
                    'admin_access', 'manage_settings',
                    # User management
                    'read_users', 'create_users', 'update_users', 'delete_users',
                    'manage_users',
                    # Role management
                    'read_roles', 'create_roles', 'update_roles', 'delete_roles',
                    'manage_roles',
                    # Permission management
                    'read_permissions', 'create_permissions', 'update_permissions',
                    'delete_permissions', 'manage_permissions',
                    # Resource management
                    'read_resources', 'create_resources', 'update_resources',
                    'delete_resources', 'manage_resources',
                    # Document management
                    'read_documents', 'write_documents', 'delete_documents',
                    'create_documents', 'update_documents',
                    # Special access
                    'read_secrets', 'view_analytics'
                ]
            },
            {
                'name': 'manager',
                'description': 'Manager with user and resource management access',
                'permissions': [
                    # User management (limited)
                    'read_users', 'create_users', 'update_users',
                    # Resource management
                    'read_resources', 'create_resources', 'update_resources',
                    'delete_resources',
                    # Document management
                    'read_documents', 'write_documents', 'delete_documents',
                    'create_documents', 'update_documents',
                    # Analytics
                    'view_analytics'
                ]
            },
            {
                'name': 'editor',
                'description': 'Content editor with document and resource management access',
                'permissions': [
                    # Resource management (limited)
                    'read_resources', 'create_resources', 'update_resources',
                    # Document management
                    'read_documents', 'write_documents', 'delete_documents',
                    'create_documents', 'update_documents'
                ]
            },
            {
                'name': 'viewer',
                'description': 'Read-only access to documents and resources',
                'permissions': [
                    'read_documents', 'read_resources'
                ]
            },
            {
                'name': 'secret_reader',
                'description': 'Can read secret information and documents',
                'permissions': [
                    'read_secrets', 'read_documents', 'read_resources'
                ]
            },
            {
                'name': 'analyst',
                'description': 'Can view analytics and read-only access to most resources',
                'permissions': [
                    'read_documents', 'read_resources', 'view_analytics'
                ]
            }
        ]

        roles = {}
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                name=role_data['name'],
                defaults={'description': role_data['description']}
            )
            roles[role_data['name']] = role

            # Assign permissions to role
            role_permissions = [permissions[perm_code] for perm_code in role_data['permissions']]
            role.permissions.set(role_permissions)

            if created:
                self.stdout.write(f'Created role: {role.name}')

        # Create admin user
        admin_user, created = User.objects.get_or_create(
            email='admin@example.com',
            defaults={
                'first_name': 'Admin',
                'last_name': 'User',
                'is_staff': True,
                'is_superuser': True
            }
        )

        if created:
            admin_user.set_password('admin123')
            admin_user.save()
            self.stdout.write('Created admin user: admin@example.com / admin123')
        else:
            self.stdout.write('Admin user already exists')

        # Assign admin role to admin user
        admin_role = roles['admin']
        UserRole.objects.get_or_create(
            user=admin_user,
            role=admin_role
        )

        # Create demo users
        demo_users = [
            {'email': 'manager@example.com', 'first_name': 'Manager',
             'last_name': 'User', 'role': 'manager'},
            {'email': 'editor@example.com', 'first_name': 'Editor',
             'last_name': 'User', 'role': 'editor'},
            {'email': 'viewer@example.com', 'first_name': 'Viewer',
             'last_name': 'User', 'role': 'viewer'},
            {'email': 'secret@example.com', 'first_name': 'Secret',
             'last_name': 'Reader', 'role': 'secret_reader'},
            {'email': 'analyst@example.com', 'first_name': 'Analyst',
             'last_name': 'User', 'role': 'analyst'},
        ]

        for user_data in demo_users:
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults={
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name']
                }
            )

            if created:
                user.set_password('password123')
                user.save()
                self.stdout.write(f'Created user: {user.email} / password123')

            # Assign role
            role = roles[user_data['role']]
            UserRole.objects.get_or_create(
                user=user,
                role=role
            )

        # Create demo resources
        demo_resources = [
            {
                'name': 'Public Document',
                'description': 'A public document that anyone with read access can view',
                'content': 'This is a public document. Anyone with read_documents '
                           'permission can access this.',
                'permission_required': 'read_documents',
                'created_by': admin_user
            },
            {
                'name': 'Secret Document',
                'description': 'A secret document requiring special permission',
                'content': 'This is a secret document. Only users with read_secrets '
                           'permission can access this.',
                'permission_required': 'read_secrets',
                'created_by': admin_user
            },
            {
                'name': 'Admin Only Document',
                'description': 'A document only admins can access',
                'content': 'This is an admin-only document. Only administrators '
                           'can access this.',
                'permission_required': 'admin_access',
                'created_by': admin_user
            },
            {
                'name': 'Manager Resource',
                'description': 'A resource that managers can access',
                'content': 'This resource is accessible to users with manager or '
                           'admin roles.',
                'permission_required': 'read_resources',
                'created_by': admin_user
            },
            {
                'name': 'Analytics Report',
                'description': 'A report that analysts can view',
                'content': 'This analytics report contains system statistics and metrics.',
                'permission_required': 'view_analytics',
                'created_by': admin_user
            },
            {
                'name': 'User Management Guide',
                'description': 'A guide for user management operations',
                'content': 'This guide explains how to manage users in the system.',
                'permission_required': 'read_users',
                'created_by': admin_user
            }
        ]

        for resource_data in demo_resources:
            resource, created = Resource.objects.get_or_create(
                name=resource_data['name'],
                defaults=resource_data
            )
            if created:
                self.stdout.write(f'Created resource: {resource.name}')

        self.stdout.write(
            self.style.SUCCESS('Demo data setup completed successfully!')
        )
        self.stdout.write('\nDemo users created:')
        self.stdout.write('- admin@example.com / admin123 (admin role) - Full access')
        self.stdout.write('- manager@example.com / password123 (manager role) - '
                          'User & resource management')
        self.stdout.write('- editor@example.com / password123 (editor role) - '
                          'Content management')
        self.stdout.write('- viewer@example.com / password123 (viewer role) - '
                          'Read-only access')
        self.stdout.write('- secret@example.com / password123 (secret_reader role) - '
                          'Secret access')
        self.stdout.write('- analyst@example.com / password123 (analyst role) - '
                          'Analytics access')
        self.stdout.write('\nDemo resources created:')
        self.stdout.write('- Public Document (read_documents)')
        self.stdout.write('- Secret Document (read_secrets)')
        self.stdout.write('- Admin Only Document (admin_access)')
        self.stdout.write('- Manager Resource (read_resources)')
        self.stdout.write('- Analytics Report (view_analytics)')
        self.stdout.write('- User Management Guide (read_users)')
        self.stdout.write('\nVisit http://localhost:8000/demo/ to test the system!')
