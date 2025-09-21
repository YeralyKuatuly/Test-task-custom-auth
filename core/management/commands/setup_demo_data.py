from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from authorization.models import Role, Permission, UserRole, RolePermission
from resources.models import Resource

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up demo data for the authentication system'

    def handle(self, *args, **options):
        self.stdout.write('Setting up demo data...')

        # Create permissions
        permissions_data = [
            {'code': 'read_documents', 'description': 'Read documents', 'element': 'documents'},
            {'code': 'write_documents', 'description': 'Write documents', 'element': 'documents'},
            {'code': 'delete_documents', 'description': 'Delete documents', 'element': 'documents'},
            {'code': 'manage_users', 'description': 'Manage users', 'element': 'users'},
            {'code': 'manage_roles', 'description': 'Manage roles', 'element': 'roles'},
            {'code': 'manage_permissions', 'description': 'Manage permissions', 'element': 'permissions'},
            {'code': 'read_secrets', 'description': 'Read secret information', 'element': 'secrets'},
            {'code': 'admin_access', 'description': 'Full admin access', 'element': 'admin'},
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
                'description': 'System administrator with full access',
                'permissions': ['admin_access', 'manage_users', 'manage_roles', 'manage_permissions', 'read_documents', 'write_documents', 'delete_documents', 'read_secrets']
            },
            {
                'name': 'editor',
                'description': 'Content editor with document management access',
                'permissions': ['read_documents', 'write_documents', 'delete_documents']
            },
            {
                'name': 'viewer',
                'description': 'Read-only access to documents',
                'permissions': ['read_documents']
            },
            {
                'name': 'secret_reader',
                'description': 'Can read secret information',
                'permissions': ['read_secrets', 'read_documents']
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
            {'email': 'editor@example.com', 'first_name': 'Editor', 'last_name': 'User', 'role': 'editor'},
            {'email': 'viewer@example.com', 'first_name': 'Viewer', 'last_name': 'User', 'role': 'viewer'},
            {'email': 'secret@example.com', 'first_name': 'Secret', 'last_name': 'Reader', 'role': 'secret_reader'},
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
                'description': 'A public document that anyone can read',
                'content': 'This is a public document. Anyone with read_documents permission can access this.',
                'permission_required': 'read_documents',
                'created_by': admin_user
            },
            {
                'name': 'Secret Document',
                'description': 'A secret document requiring special permission',
                'content': 'This is a secret document. Only users with read_secrets permission can access this.',
                'permission_required': 'read_secrets',
                'created_by': admin_user
            },
            {
                'name': 'Admin Only Document',
                'description': 'A document only admins can access',
                'content': 'This is an admin-only document. Only administrators can access this.',
                'permission_required': 'admin_access',
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
        self.stdout.write('- admin@example.com / admin123 (admin role)')
        self.stdout.write('- editor@example.com / password123 (editor role)')
        self.stdout.write('- viewer@example.com / password123 (viewer role)')
        self.stdout.write('- secret@example.com / password123 (secret_reader role)')
        self.stdout.write('\nVisit http://localhost:8000/demo/ to test the system!')
