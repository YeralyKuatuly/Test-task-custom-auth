from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.http import require_http_methods
from .auth_decorators import jwt_login_required
import json


# Authentication Views
def login_view(request):
    """Render login page"""
    return render(request, 'login.html')


def register_view(request):
    """Render register page"""
    return render(request, 'register.html')


def dashboard_view(request):
    """Render dashboard page"""
    return render(request, 'dashboard.html')


# Demo Views
def demo_view(request):
    """
    Demo page for testing the authentication and authorization system
    """
    return render(request, 'demo.html')


def detailed_demo_view(request):
    """
    Detailed demo page for comprehensive RBAC testing
    """
    return render(request, 'detailed_demo.html')


# API Views
@csrf_exempt
@require_http_methods(["POST"])
def api_login_view(request):
    """API endpoint for login (alternative to DRF view)"""
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'detail': 'Email and password required'}, status=400)

        user = authenticate(request, email=email, password=password)

        if user and user.is_active:
            login(request, user)
            # Generate JWT tokens (you might want to use your existing JWT service)
            from .jwt_service import JWTService
            access_token = JWTService.create_access_token(user)
            refresh_token = JWTService.create_refresh_token(user)

            return JsonResponse({
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                }
            })
        else:
            return JsonResponse({'detail': 'Invalid credentials'}, status=401)

    except json.JSONDecodeError:
        return JsonResponse({'detail': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'detail': 'Login failed'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def api_logout_view(request):
    """API endpoint for logout"""
    try:
        logout(request)
        return JsonResponse({'detail': 'Successfully logged out'})
    except Exception as e:
        return JsonResponse({'detail': 'Logout failed'}, status=500)
