from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from core.views import login_view, register_view, dashboard_view, api_login_view, api_logout_view


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('auth_api.urls')),
    path('api/authorization/', include('authorization.urls')),
    path('api/resources/', include('resources.urls')),
    path('', include('core.urls')),

    # Authentication pages
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('api/web/login/', api_login_view, name='web_login'),
    path('api/web/logout/', api_logout_view, name='web_logout'),

    # Documentation URLs
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'),
         name='swagger-ui'),
]

# Serve static files during development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
