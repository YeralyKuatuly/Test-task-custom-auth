from django.shortcuts import render


def demo_view(request):
    """
    Demo page for testing the authentication and authorization system
    """
    return render(request, 'demo.html')
