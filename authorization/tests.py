from django.test import TestCase
from django.contrib.auth import get_user_model
from .models import Permission, Role

User = get_user_model()


class PermissionModelTest(TestCase):
    """Test cases for Permission model"""

    def setUp(self):
        self.permission_data = {
            'code': 'read_documents',
            'description': 'Read documents permission',
            'element': 'documents'
        }

    def test_create_permission(self):
        """Test permission creation"""
        permission = Permission.objects.create(**self.permission_data)
        self.assertEqual(permission.code, 'read_documents')
        self.assertEqual(permission.description, 'Read documents permission')
        self.assertEqual(permission.element, 'documents')

    def test_permission_str_representation(self):
        """Test permission string representation"""
        permission = Permission.objects.create(**self.permission_data)
        self.assertEqual(str(permission), 'documents: read_documents')

    def test_permission_unique_code(self):
        """Test permission code uniqueness"""
        Permission.objects.create(**self.permission_data)
        with self.assertRaises(Exception):
            Permission.objects.create(**self.permission_data)


class RoleModelTest(TestCase):
    """Test cases for Role model"""

    def setUp(self):
        self.role_data = {
            'name': 'editor',
            'description': 'Content editor role'
        }
        self.permission = Permission.objects.create(
            code='read_documents',
            description='Read documents',
            element='documents'
        )

    def test_create_role(self):
        """Test role creation"""
        role = Role.objects.create(**self.role_data)
        self.assertEqual(role.name, 'editor')
        self.assertEqual(role.description, 'Content editor role')

    def test_role_str_representation(self):
        """Test role string representation"""
        role = Role.objects.create(**self.role_data)
        self.assertEqual(str(role), 'editor')

    def test_role_permission_relationship(self):
        """Test role-permission relationship"""
        role = Role.objects.create(**self.role_data)
        role.permissions.add(self.permission)
        self.assertIn(self.permission, role.permissions.all())

    def test_role_unique_name(self):
        """Test role name uniqueness"""
        Role.objects.create(**self.role_data)
        with self.assertRaises(Exception):
            Role.objects.create(**self.role_data)
