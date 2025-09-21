from django.urls import path
from . import views


urlpatterns = [
    path('demo/', views.demo_view, name='demo'),
    path('detailed-demo/', views.detailed_demo_view, name='detailed_demo'),
]
