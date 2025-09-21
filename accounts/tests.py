from django.test import TestCase
from django.contrib.auth import get_user_model
from .serializers import (
    UserSerializer, UserRegistrationSerializer, UserUpdateSerializer
)

User = get_user_model()


class UserModelTest(TestCase):
    """Test cases for User model"""

    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }

    def test_create_user(self):
        """Test user creation"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'Test')
        self.assertEqual(user.last_name, 'User')
        self.assertTrue(user.check_password('testpass123'))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        """Test superuser creation"""
        user = User.objects.create_superuser(**self.user_data)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_user_str_representation(self):
        """Test user string representation"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(str(user), 'test@example.com')

    def test_get_full_name(self):
        """Test get_full_name method"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.get_full_name(), 'Test User')

    def test_get_short_name(self):
        """Test get_short_name method"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.get_short_name(), 'Test')

    def test_soft_delete(self):
        """Test soft delete functionality"""
        user = User.objects.create_user(**self.user_data)
        user.soft_delete()
        self.assertFalse(user.is_active)
        self.assertTrue(user.is_deleted)
        self.assertIsNotNone(user.deleted_at)

    def test_email_normalization(self):
        """Test email normalization"""
        user = User.objects.create_user(
            email='TEST@EXAMPLE.COM',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )
        # Django's normalize_email only normalizes the domain part
        self.assertEqual(user.email, 'TEST@example.com')


class UserSerializerTest(TestCase):
    """Test cases for User serializers"""

    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_user_serializer(self):
        """Test UserSerializer"""
        serializer = UserSerializer(self.user)
        data = serializer.data

        self.assertEqual(data['email'], 'test@example.com')
        self.assertEqual(data['first_name'], 'Test')
        self.assertEqual(data['last_name'], 'User')
        self.assertTrue(data['is_active'])
        self.assertIn('id', data)
        self.assertIn('created_at', data)
        self.assertIn('updated_at', data)

    def test_user_registration_serializer_valid(self):
        """Test UserRegistrationSerializer with valid data"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_user_registration_serializer_invalid_email(self):
        """Test UserRegistrationSerializer with invalid email"""
        data = {
            'email': 'invalid-email',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_user_registration_serializer_duplicate_email(self):
        """Test UserRegistrationSerializer with duplicate email"""
        data = {
            'email': 'test@example.com',  # Already exists
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_user_registration_serializer_password_mismatch(self):
        """Test UserRegistrationSerializer with password mismatch"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123',
            'password_confirm': 'differentpass123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)

    def test_user_registration_serializer_weak_password(self):
        """Test UserRegistrationSerializer with weak password"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': '123',  # Too short
            'password_confirm': '123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

    def test_user_registration_serializer_password_no_digit(self):
        """Test UserRegistrationSerializer with password without digit"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'passwordonly',
            'password_confirm': 'passwordonly'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

    def test_user_registration_serializer_password_no_letter(self):
        """Test UserRegistrationSerializer with password without letter"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': '12345678',
            'password_confirm': '12345678'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

    def test_user_registration_serializer_short_names(self):
        """Test UserRegistrationSerializer with short names"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'A',  # Too short
            'last_name': 'B',   # Too short
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('first_name', serializer.errors)
        self.assertIn('last_name', serializer.errors)

    def test_user_update_serializer(self):
        """Test UserUpdateSerializer"""
        data = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        serializer = UserUpdateSerializer(self.user, data=data)
        self.assertTrue(serializer.is_valid())
        updated_user = serializer.save()
        self.assertEqual(updated_user.first_name, 'Updated')
        self.assertEqual(updated_user.last_name, 'Name')
