from functools import wraps
from django.http import JsonResponse
from django.shortcuts import redirect
from core.jwt_service import JWTService
from accounts.models import User


def jwt_login_required(view_func):
    """
    Custom decorator that checks JWT token authentication
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Get token from Authorization header or query parameter
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        token = None

        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            # Try to get token from query parameter (for testing)
            token = request.GET.get('token')

        if not token:
            # Check if this is an AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Authentication required'}, status=401)
            else:
                # Redirect to login for regular requests
                return redirect('/login/')

        try:
            # Decode and validate the JWT token
            payload = JWTService.decode_access_token(token)
            user_id = payload.get('user_id')

            if not user_id:
                raise ValueError("Invalid token payload")

            # Get the user
            try:
                user = User.objects.get(id=user_id, is_active=True)
                request.user = user
                return view_func(request, *args, **kwargs)
            except User.DoesNotExist:
                raise ValueError("User not found")

        except Exception as e:
            print(f"JWT authentication error: {e}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Invalid token'}, status=401)
            else:
                return redirect('/login/')

    return wrapper
