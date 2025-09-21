from rest_framework import serializers
from .models import Role, Permission, UserRole, RolePermission
from accounts.models import User


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'code', 'description', 'element', 'created_at',
                  'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_code(self, value):
        """Validate permission code"""
        if not value or len(value.strip()) < 3:
            raise serializers.ValidationError(
                "Permission code must be at least 3 characters long"
            )

        # Check for uniqueness
        if self.instance and self.instance.code == value:
            return value

        if Permission.objects.filter(code=value).exists():
            raise serializers.ValidationError(
                "Permission with this code already exists"
            )

        return value.strip().lower()

    def validate_element(self, value):
        """Validate element name"""
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError(
                "Element must be at least 2 characters long"
            )
        return value.strip().lower()

    def validate_description(self, value):
        """Validate description"""
        if not value or len(value.strip()) < 5:
            raise serializers.ValidationError(
                "Description must be at least 5 characters long"
            )
        return value.strip()


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)
    permission_ids = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        help_text="List of permission IDs to assign to this role"
    )

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions', 'permission_ids',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_name(self, value):
        """Validate role name"""
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError(
                "Role name must be at least 2 characters long"
            )

        # Check for uniqueness
        if self.instance and self.instance.name == value:
            return value

        if Role.objects.filter(name=value).exists():
            raise serializers.ValidationError(
                "Role with this name already exists"
            )

        return value.strip().lower()

    def validate_description(self, value):
        """Validate description"""
        if value and len(value.strip()) < 5:
            raise serializers.ValidationError(
                "Description must be at least 5 characters long"
            )
        return value.strip() if value else value

    def validate_permission_ids(self, value):
        """Validate permission IDs"""
        if value:
            # Check if all permission IDs exist
            existing_permissions = Permission.objects.filter(id__in=value)
            if len(existing_permissions) != len(value):
                raise serializers.ValidationError(
                    "One or more permission IDs do not exist"
                )
        return value

    def create(self, validated_data):
        """Create role with permissions"""
        permission_ids = validated_data.pop('permission_ids', [])
        role = Role.objects.create(**validated_data)

        if permission_ids:
            permissions = Permission.objects.filter(id__in=permission_ids)
            role.permissions.set(permissions)

        return role

    def update(self, instance, validated_data):
        """Update role with permissions"""
        permission_ids = validated_data.pop('permission_ids', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if permission_ids is not None:
            permissions = Permission.objects.filter(id__in=permission_ids)
            instance.permissions.set(permissions)

        return instance


class UserRoleSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)

    class Meta:
        model = UserRole
        fields = ['id', 'user', 'role', 'user_email', 'role_name',
                  'assigned_at']
        read_only_fields = ['id', 'assigned_at']

    def validate_user(self, value):
        """Validate user exists and is active"""
        if not value.is_active:
            raise serializers.ValidationError(
                "Cannot assign role to inactive user"
            )
        return value

    def validate_role(self, value):
        """Validate role exists"""
        if not value:
            raise serializers.ValidationError("Role is required")
        return value

    def validate(self, attrs):
        """Cross-field validation"""
        user = attrs.get('user')
        role = attrs.get('role')

        if user and role:
            # Check if user already has this role
            if UserRole.objects.filter(user=user, role=role).exists():
                raise serializers.ValidationError(
                    "User already has this role"
                )

        return attrs


class RolePermissionSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(source='role.name', read_only=True)
    permission_code = serializers.CharField(
        source='permission.code', read_only=True
    )

    class Meta:
        model = RolePermission
        fields = ['id', 'role', 'permission', 'role_name', 'permission_code',
                  'created_at']
        read_only_fields = ['id', 'created_at']

    def validate_role(self, value):
        """Validate role exists"""
        if not value:
            raise serializers.ValidationError("Role is required")
        return value

    def validate_permission(self, value):
        """Validate permission exists"""
        if not value:
            raise serializers.ValidationError("Permission is required")
        return value

    def validate(self, attrs):
        """Cross-field validation"""
        role = attrs.get('role')
        permission = attrs.get('permission')

        if role and permission:
            # Check if role already has this permission
            if RolePermission.objects.filter(
                role=role, permission=permission
            ).exists():
                raise serializers.ValidationError(
                    "Role already has this permission"
                )

        return attrs


class UserRoleAssignmentSerializer(serializers.Serializer):
    """Serializer for assigning roles to users"""
    user_id = serializers.UUIDField()
    role_ids = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="List of role IDs to assign to the user"
    )

    def validate_user_id(self, value):
        """Validate user exists and is active"""
        try:
            User.objects.get(id=value, is_active=True)
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User not found or inactive"
            )

    def validate_role_ids(self, value):
        """Validate role IDs exist"""
        if not value:
            raise serializers.ValidationError(
                "At least one role must be specified"
            )

        existing_roles = Role.objects.filter(id__in=value)
        if len(existing_roles) != len(value):
            raise serializers.ValidationError(
                "One or more role IDs do not exist"
            )

        return value

    def validate(self, attrs):
        """Cross-field validation"""
        user_id = attrs.get('user_id')
        role_ids = attrs.get('role_ids')

        if user_id and role_ids:
            # Check for existing role assignments
            existing_assignments = UserRole.objects.filter(
                user_id=user_id,
                role_id__in=role_ids
            ).values_list('role_id', flat=True)

            if existing_assignments:
                raise serializers.ValidationError(
                    f"User already has roles with IDs: "
                    f"{list(existing_assignments)}"
                )

        return attrs
