from django.shortcuts import render


def demo_view(request):
    """
    Demo page for testing the authentication and authorization system
    """
    return render(request, 'demo.html')


def detailed_demo_view(request):
    """
    Detailed demo page for comprehensive RBAC testing
    """
    return render(request, 'detailed_demo.html')
