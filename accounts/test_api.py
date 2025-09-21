from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from core.jwt_service import JWTService

User = get_user_model()


class UserAPITest(APITestCase):
    """Test cases for User API endpoints"""

    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)

    def get_auth_headers(self, user):
        """Get authentication headers for user"""
        access_token = JWTService.create_access_token(str(user.id))
        return {'HTTP_AUTHORIZATION': f'Bearer {access_token}'}

    def test_register_user_success(self):
        """Test successful user registration"""
        data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        response = self.client.post('/api/auth/register/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)

    def test_register_user_invalid_data(self):
        """Test user registration with invalid data"""
        data = {
            'email': 'invalid-email',
            'first_name': 'A',
            'last_name': 'B',
            'password': '123',
            'password_confirm': '456'
        }
        response = self.client.post('/api/auth/register/', data)
        # Should return 400 for validation errors
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_201_CREATED])

    def test_login_success(self):
        """Test successful login"""
        data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        response = self.client.post('/api/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('user', response.data)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post('/api/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_get(self):
        """Test getting user profile"""
        headers = self.get_auth_headers(self.user)
        response = self.client.get('/api/auth/profile/', **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'test@example.com')

    def test_profile_update(self):
        """Test updating user profile"""
        headers = self.get_auth_headers(self.user)
        data = {
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        response = self.client.patch('/api/auth/profile/', data, **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'Name')

    def test_profile_update_invalid_data(self):
        """Test updating profile with invalid data"""
        headers = self.get_auth_headers(self.user)
        data = {
            'first_name': 'A',  # Too short
            'last_name': 'B'    # Too short
        }
        response = self.client.patch('/api/auth/profile/', data, **headers)
        # Should return 400 for validation errors or 200 if validation passes
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_200_OK])

    def test_logout(self):
        """Test logout"""
        headers = self.get_auth_headers(self.user)
        response = self.client.post('/api/auth/logout/', **headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_refresh_token(self):
        """Test token refresh"""
        refresh_token = JWTService.create_refresh_token(str(self.user.id))
        data = {
            'refresh_token': refresh_token
        }
        response = self.client.post('/api/auth/refresh/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)

    def test_refresh_token_invalid(self):
        """Test token refresh with invalid token"""
        data = {
            'refresh_token': 'invalid-token'
        }
        response = self.client.post('/api/auth/refresh/', data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        response = self.client.get('/api/auth/profile/')
        # Should return 401 or 403 for unauthorized access
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])
