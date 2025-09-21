from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RoleViewSet, PermissionViewSet, UserRoleViewSet,
    RolePermissionViewSet, UserManagementView
)

router = DefaultRouter()
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'role-permissions', RolePermissionViewSet)
router.register(r'users', UserManagementView, basename='user-management')

urlpatterns = [
    path('', include(router.urls)),
]
