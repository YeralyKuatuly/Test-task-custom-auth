from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class Permission(models.Model):
    """Permission model for granular access control"""
    code = models.CharField(max_length=100, unique=True,
                            help_text="Unique permission code")
    description = models.TextField(help_text="Description of what "
                                   "this permission allows")
    element = models.CharField(max_length=50, help_text="UI element or "
                               "feature this permission relates to")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'permissions'
        ordering = ['element', 'code']

    def __str__(self):
        return f"{self.element}: {self.code}"


class Role(models.Model):
    """Role model for grouping permissions"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, help_text="Description of "
                                   "this role")
    permissions = models.ManyToManyField(
        Permission,
        through='RolePermission',
        related_name='roles',
        blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'roles'
        ordering = ['name']

    def __str__(self):
        return self.name


class UserRole(models.Model):
    """Through model for User-Role many-to-many relationship"""
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE)
    role = models.ForeignKey('authorization.Role', on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_roles'
        unique_together = ['user', 'role']

    def __str__(self):
        return f"{self.user.email} - {self.role.name}"


class RolePermission(models.Model):
    """Through model for Role-Permission many-to-many relationship"""
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'role_permissions'
        unique_together = ['role', 'permission']
        ordering = ['role', 'permission']

    def __str__(self):
        return f"{self.role.name} - {self.permission.code}"
