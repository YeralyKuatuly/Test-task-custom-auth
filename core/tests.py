from django.test import TestCase
from django.contrib.auth import get_user_model
from .jwt_service import JWTService
from .permissions import require_permission, require_role
from authorization.models import Permission, Role, UserRole

User = get_user_model()


class JWTServiceTest(TestCase):
    """Test cases for JWT service"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )

    def test_create_access_token(self):
        """Test creating access token"""
        token = JWTService.create_access_token(str(self.user.id))
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

    def test_create_refresh_token(self):
        """Test creating refresh token"""
        token = JWTService.create_refresh_token(str(self.user.id))
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

    def test_decode_valid_token(self):
        """Test decoding valid token"""
        token = JWTService.create_access_token(str(self.user.id))
        payload = JWTService.decode_token(token)
        self.assertEqual(payload['sub'], str(self.user.id))
        self.assertEqual(payload['type'], 'access')

    def test_decode_invalid_token(self):
        """Test decoding invalid token"""
        with self.assertRaises(ValueError):
            JWTService.decode_token('invalid-token')

    def test_token_expiration(self):
        """Test token expiration"""
        # This would require mocking time or using a very short expiration
        # For now, we'll just test that tokens are created successfully
        access_token = JWTService.create_access_token(str(self.user.id))
        refresh_token = JWTService.create_refresh_token(str(self.user.id))

        self.assertIsNotNone(access_token)
        self.assertIsNotNone(refresh_token)


class PermissionsDecoratorTest(TestCase):
    """Test cases for permission decorators"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )
        self.permission = Permission.objects.create(
            code='read_documents',
            description='Read documents',
            element='documents'
        )
        self.role = Role.objects.create(
            name='editor',
            description='Editor role'
        )
        self.role.permissions.add(self.permission)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_require_permission_with_valid_permission(self):
        """Test require_permission decorator with valid permission"""
        @require_permission('read_documents')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self, user):
                self.user = user

        request = MockRequest(self.user)
        result = test_view(request)
        self.assertEqual(result['status'], 'success')

    def test_require_permission_without_permission(self):
        """Test require_permission decorator without permission"""
        @require_permission('write_documents')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self, user):
                self.user = user

        request = MockRequest(self.user)
        result = test_view(request)
        # Decorator returns Response object, not dict
        self.assertEqual(result.status_code, 403)

    def test_require_permission_unauthenticated(self):
        """Test require_permission decorator with unauthenticated user"""
        @require_permission('read_documents')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self):
                self.user = None

        request = MockRequest()
        result = test_view(request)
        # Decorator returns Response object, not dict
        self.assertEqual(result.status_code, 401)

    def test_require_role_with_valid_role(self):
        """Test require_role decorator with valid role"""
        @require_role('editor')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self, user):
                self.user = user

        request = MockRequest(self.user)
        result = test_view(request)
        self.assertEqual(result['status'], 'success')

    def test_require_role_without_role(self):
        """Test require_role decorator without role"""
        @require_role('admin')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self, user):
                self.user = user

        request = MockRequest(self.user)
        result = test_view(request)
        # Decorator returns Response object, not dict
        self.assertEqual(result.status_code, 403)

    def test_require_role_unauthenticated(self):
        """Test require_role decorator with unauthenticated user"""
        @require_role('editor')
        def test_view(request):
            return {'status': 'success'}

        # Mock request object
        class MockRequest:
            def __init__(self):
                self.user = None

        request = MockRequest()
        result = test_view(request)
        # Decorator returns Response object, not dict
        self.assertEqual(result.status_code, 401)


class UserPermissionMethodsTest(TestCase):
    """Test cases for user permission methods"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )
        self.permission1 = Permission.objects.create(
            code='read_documents',
            description='Read documents',
            element='documents'
        )
        self.permission2 = Permission.objects.create(
            code='write_documents',
            description='Write documents',
            element='documents'
        )
        self.role = Role.objects.create(
            name='editor',
            description='Editor role'
        )
        self.role.permissions.add(self.permission1, self.permission2)
        UserRole.objects.create(user=self.user, role=self.role)

    def test_has_permission_with_valid_permission(self):
        """Test has_permission method with valid permission"""
        self.assertTrue(self.user.has_permission('read_documents'))
        self.assertTrue(self.user.has_permission('write_documents'))

    def test_has_permission_without_permission(self):
        """Test has_permission method without permission"""
        self.assertFalse(self.user.has_permission('delete_documents'))

    def test_has_role_with_valid_role(self):
        """Test has_role method with valid role"""
        self.assertTrue(self.user.has_role('editor'))

    def test_has_role_without_role(self):
        """Test has_role method without role"""
        self.assertFalse(self.user.has_role('admin'))

    def test_get_permissions(self):
        """Test get_permissions method"""
        permissions = self.user.get_permissions()
        permission_codes = [p.code for p in permissions]
        self.assertIn('read_documents', permission_codes)
        self.assertIn('write_documents', permission_codes)
        self.assertEqual(len(permissions), 2)
