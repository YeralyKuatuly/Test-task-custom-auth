from django.urls import path
from django.shortcuts import redirect
from . import views


def root_redirect(request):
    """Redirect root URL to login page"""
    return redirect('/login/')


urlpatterns = [
    path('', root_redirect, name='root'),
    path('demo/', views.demo_view, name='demo'),
    path('detailed-demo/', views.detailed_demo_view, name='detailed_demo'),
]
