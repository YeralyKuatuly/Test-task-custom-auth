from rest_framework import serializers
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from .models import User


class UserSerializer(serializers.ModelSerializer):
    roles = serializers.StringRelatedField(many=True, read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'is_active',
                  'roles', 'permissions', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_permissions(self, obj):
        """Get all permissions for this user through their roles"""
        return [perm.code for perm in obj.get_permissions()]

    def validate_email(self, value):
        """Validate email format and uniqueness"""
        try:
            validate_email(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Invalid email format")

        if self.instance and self.instance.email == value:
            return value

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "User with this email already exists"
            )

        return value

    def validate_first_name(self, value):
        """Validate first name"""
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError(
                "First name must be at least 2 characters long"
            )
        return value.strip() if value else value

    def validate_last_name(self, value):
        """Validate last name"""
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError(
                "Last name must be at least 2 characters long"
            )
        return value.strip() if value else value


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        help_text="Password must be at least 8 characters long"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        help_text="Confirm your password"
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password',
                  'password_confirm']

    def validate_email(self, value):
        """Validate email format and uniqueness"""
        try:
            validate_email(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Invalid email format")

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "User with this email already exists"
            )

        return value.lower().strip()

    def validate_first_name(self, value):
        """Validate first name"""
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError(
                "First name is required and must be at least 2 characters long"
            )
        return value.strip()

    def validate_last_name(self, value):
        """Validate last name"""
        if not value or len(value.strip()) < 2:
            raise serializers.ValidationError(
                "Last name is required and must be at least 2 characters long"
            )
        return value.strip()

    def validate_password(self, value):
        """Validate password strength"""
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long"
            )

        # Check for at least one digit
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError(
                "Password must contain at least one digit"
            )

        # Check for at least one letter
        if not any(char.isalpha() for char in value):
            raise serializers.ValidationError(
                "Password must contain at least one letter"
            )

        return value

    def validate(self, attrs):
        """Cross-field validation"""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs

    def create(self, validated_data):
        """Create user with validated data"""
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""

    class Meta:
        model = User
        fields = ['first_name', 'last_name']

    def validate_first_name(self, value):
        """Validate first name"""
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError(
                "First name must be at least 2 characters long"
            )
        return value.strip() if value else value

    def validate_last_name(self, value):
        """Validate last name"""
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError(
                "Last name must be at least 2 characters long"
            )
        return value.strip() if value else value
