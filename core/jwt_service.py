import jwt
from django.conf import settings
from datetime import datetime, timedelta
from typing import Dict, Optional


class JWTService:
    @staticmethod
    def create_access_token(user_id: str, payload: Optional[Dict] = None) -> str:
        """Create access token"""
        if payload is None:
            payload = {}

        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        payload.update({
            'exp': expire,
            'iat': datetime.utcnow(),
            'sub': str(user_id),
            'type': 'access'
        })

        return jwt.encode(
            payload,
            settings.JWT_SECRET_KEY,
            algorithm='HS256'
        )

    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """Create refresh token"""
        expire = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        payload = {
            'exp': expire,
            'iat': datetime.utcnow(),
            'sub': str(user_id),
            'type': 'refresh'
        }

        return jwt.encode(
            payload,
            settings.JWT_SECRET_KEY,
            algorithm='HS256'
        )

    @staticmethod
    def decode_token(token: str) -> Dict:
        """Decode and validate JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=['HS256']
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError('Token expired')
        except jwt.InvalidTokenError:
            raise ValueError('Invalid token')
