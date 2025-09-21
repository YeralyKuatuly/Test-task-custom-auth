from rest_framework import serializers
from .models import Resource
from authorization.models import Permission


class ResourceSerializer(serializers.ModelSerializer):
    created_by_email = serializers.CharField(
        source='created_by.email', read_only=True
    )

    class Meta:
        model = Resource
        fields = ['id', 'name', 'description', 'content',
                  'permission_required', 'created_by', 'created_by_email',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'created_by', 'created_by_email',
                            'created_at', 'updated_at']

    def validate_name(self, value):
        """Validate resource name"""
        if not value or len(value.strip()) < 3:
            raise serializers.ValidationError(
                "Resource name must be at least 3 characters long"
            )
        return value.strip()

    def validate_description(self, value):
        """Validate description"""
        if value and len(value.strip()) < 5:
            raise serializers.ValidationError(
                "Description must be at least 5 characters long"
            )
        return value.strip() if value else value

    def validate_content(self, value):
        """Validate content"""
        if not value or len(value.strip()) < 10:
            raise serializers.ValidationError(
                "Content must be at least 10 characters long"
            )
        return value.strip()

    def validate_permission_required(self, value):
        """Validate permission exists"""
        if not value:
            raise serializers.ValidationError("Permission is required")

        # Check if permission exists
        if not Permission.objects.filter(code=value).exists():
            raise serializers.ValidationError(
                "Permission with this code does not exist"
            )

        return value.strip().lower()


class ResourceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = ['name', 'description', 'content', 'permission_required']

    def validate_name(self, value):
        """Validate resource name"""
        if not value or len(value.strip()) < 3:
            raise serializers.ValidationError(
                "Resource name must be at least 3 characters long"
            )
        return value.strip()

    def validate_description(self, value):
        """Validate description"""
        if value and len(value.strip()) < 5:
            raise serializers.ValidationError(
                "Description must be at least 5 characters long"
            )
        return value.strip() if value else value

    def validate_content(self, value):
        """Validate content"""
        if not value or len(value.strip()) < 10:
            raise serializers.ValidationError(
                "Content must be at least 10 characters long"
            )
        return value.strip()

    def validate_permission_required(self, value):
        """Validate permission exists"""
        if not value:
            raise serializers.ValidationError("Permission is required")

        # Check if permission exists
        if not Permission.objects.filter(code=value).exists():
            raise serializers.ValidationError(
                "Permission with this code does not exist"
            )

        return value.strip().lower()

    def create(self, validated_data):
        """Create resource with validated data"""
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)


class ResourceUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating resources"""

    class Meta:
        model = Resource
        fields = ['name', 'description', 'content']

    def validate_name(self, value):
        """Validate resource name"""
        if value and len(value.strip()) < 3:
            raise serializers.ValidationError(
                "Resource name must be at least 3 characters long"
            )
        return value.strip() if value else value

    def validate_description(self, value):
        """Validate description"""
        if value and len(value.strip()) < 5:
            raise serializers.ValidationError(
                "Description must be at least 5 characters long"
            )
        return value.strip() if value else value

    def validate_content(self, value):
        """Validate content"""
        if value and len(value.strip()) < 10:
            raise serializers.ValidationError(
                "Content must be at least 10 characters long"
            )
        return value.strip() if value else value
