from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ResourceViewSet, ResourceAccessTestView, ResourceStatsView

router = DefaultRouter()
router.register(r'resources', ResourceViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('test-access/<int:resource_id>/', ResourceAccessTestView.as_view(), name='test-resource-access'),
    path('stats/', ResourceStatsView.as_view(), name='resource-stats'),
]
