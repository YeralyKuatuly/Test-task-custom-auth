from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from .models import Role, Permission, UserRole, RolePermission
from .serializers import (
    RoleSerializer, PermissionSerializer, UserRoleSerializer,
    RolePermissionSerializer
)

User = get_user_model()


class PermissionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing permissions
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter permissions based on user permissions"""
        if self.request.user.is_superuser:
            return Permission.objects.all()

        # Regular users can only view permissions
        return Permission.objects.all()

    def perform_create(self, serializer):
        """Only superusers can create permissions"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can create permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_update(self, serializer):
        """Only superusers can update permissions"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can update permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_destroy(self, instance):
        """Only superusers can delete permissions"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can delete permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        instance.delete()


class RoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing roles
    """
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter roles based on user permissions"""
        if self.request.user.is_superuser:
            return Role.objects.all()

        # Regular users can only view roles
        return Role.objects.all()

    def perform_create(self, serializer):
        """Only superusers can create roles"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can create roles'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_update(self, serializer):
        """Only superusers can update roles"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can update roles'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_destroy(self, instance):
        """Only superusers can delete roles"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can delete roles'},
                status=status.HTTP_403_FORBIDDEN
            )
        instance.delete()


class UserRoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user-role assignments
    """
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter user roles based on permissions"""
        if self.request.user.is_superuser:
            return UserRole.objects.all()

        # Regular users can only view their own roles
        return UserRole.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Only superusers can assign roles"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can assign roles'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_update(self, serializer):
        """Only superusers can update role assignments"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can update role assignments'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_destroy(self, instance):
        """Only superusers can remove role assignments"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can remove role assignments'},
                status=status.HTTP_403_FORBIDDEN
            )
        instance.delete()


class RolePermissionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing role-permission assignments
    """
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter role permissions based on user permissions"""
        if self.request.user.is_superuser:
            return RolePermission.objects.all()

        # Regular users can only view role permissions
        return RolePermission.objects.all()

    def perform_create(self, serializer):
        """Only superusers can assign permissions to roles"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can assign permissions to roles'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_update(self, serializer):
        """Only superusers can update role-permission assignments"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can update role-permission '
                          'assignments'},
                status=status.HTTP_403_FORBIDDEN
            )
        serializer.save()

    def perform_destroy(self, instance):
        """Only superusers can remove role-permission assignments"""
        if not self.request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can remove role-permission '
                          'assignments'},
                status=status.HTTP_403_FORBIDDEN
            )
        instance.delete()


class UserManagementView(viewsets.ModelViewSet):
    """
    ViewSet for user management operations
    """
    queryset = User.objects.filter(is_active=True)
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter users based on permissions"""
        if self.request.user.is_superuser:
            return User.objects.filter(is_active=True)

        # Regular users can only view their own profile
        return User.objects.filter(id=self.request.user.id)

    def list(self, request):
        """List users (superusers only)"""
        if not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can list users'},
                status=status.HTTP_403_FORBIDDEN
            )

        users = self.get_queryset()
        return Response({
            'users': [
                {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_active': user.is_active,
                    'roles': [role.name for role in user.roles.all()]
                }
                for user in users
            ]
        })

    def retrieve(self, request, pk=None):
        """Get user details"""
        if not request.user.is_superuser and str(request.user.id) != pk:
            return Response(
                {'error': 'You can only view your own profile'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            user = User.objects.get(id=pk, is_active=True)
            return Response({
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_active': user.is_active,
                'roles': [role.name for role in user.roles.all()],
                'permissions': [perm.code for perm in user.get_permissions()]
            })
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
