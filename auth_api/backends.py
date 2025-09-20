from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from core.jwt_service import JWTService
from django.contrib.auth.backends import BaseBackend
from accounts.models import User


class JWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return None

        try:
            # Extract token from "Bearer {token}"
            token = auth_header.split(' ')[1]
            payload = JWTService.decode_token(token)

            # Check if it's an access token
            if payload.get('type') != 'access':
                raise AuthenticationFailed('Invalid token type')

            # Get user from token
            user_id = payload.get('sub')
            user = User.objects.get(id=user_id, is_active=True)

            return (user, token)

        except (IndexError, User.DoesNotExist, ValueError) as e:
            raise AuthenticationFailed('Invalid token')


class EmailAuthBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=email)
            if user.check_password(password) and user.is_active:
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id, is_active=True)
        except User.DoesNotExist:
            return None
