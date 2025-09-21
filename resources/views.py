from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from django.shortcuts import get_object_or_404
from .models import Resource
from .serializers import ResourceSerializer, ResourceCreateSerializer
from core.permissions import require_permission


class ResourceViewSet(ModelViewSet):
    """
    ViewSet for managing resources with permission-based access control
    """
    queryset = Resource.objects.all()
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Users can only see resources they have permission to access
        user_permissions = self.request.user.get_permissions().values_list('code', flat=True)
        return Resource.objects.filter(permission_required__in=user_permissions)

    def get_serializer_class(self):
        if self.action == 'create':
            return ResourceCreateSerializer
        return ResourceSerializer

    def list(self, request, *args, **kwargs):
        """
        List resources accessible to the user
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific resource if user has permission
        """
        resource = get_object_or_404(Resource, pk=kwargs['pk'])

        # Check if user has permission to access this resource
        if not request.user.has_permission(resource.permission_required):
            return Response(
                {'error': 'You do not have permission to access this resource'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(resource)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """
        Create a new resource (requires admin permission)
        """
        if not request.user.has_role('admin'):
            return Response(
                {'error': 'Only administrators can create resources'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """
        Update a resource (requires admin permission)
        """
        if not request.user.has_role('admin'):
            return Response(
                {'error': 'Only administrators can update resources'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        """
        Delete a resource (requires admin permission)
        """
        if not request.user.has_role('admin'):
            return Response(
                {'error': 'Only administrators can delete resources'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().destroy(request, *args, **kwargs)


class ResourceAccessTestView(APIView):
    """
    Test view to demonstrate permission-based access control
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, resource_id):
        """
        Test access to a specific resource
        """
        try:
            resource = Resource.objects.get(id=resource_id)

            # Check if user has permission to access this resource
            if not request.user.has_permission(resource.permission_required):
                return Response(
                    {
                        'error': 'Forbidden',
                        'message': f'You do not have permission to access resource: {resource.name}',
                        'required_permission': resource.permission_required
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            return Response({
                'message': 'Access granted',
                'resource': ResourceSerializer(resource).data
            })

        except Resource.DoesNotExist:
            return Response(
                {'error': 'Resource not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ResourceStatsView(APIView):
    """
    View for getting resource statistics
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        total_resources = Resource.objects.count()
        user_resources = Resource.objects.filter(created_by=request.user).count()

        # Count resources by permission requirement
        permission_stats = {}
        for resource in Resource.objects.all():
            perm = resource.permission_required
            permission_stats[perm] = permission_stats.get(perm, 0) + 1

        return Response({
            'total_resources': total_resources,
            'user_resources': user_resources,
            'permission_distribution': permission_stats,
            'user_info': {
                'email': request.user.email,
                'roles': [role.name for role in request.user.roles.all()],
                'permissions': [perm.code for perm in request.user.get_permissions()]
            }
        })
