from django.urls import path
from .views import login_view, custom_logout, register, home, test_db

urlpatterns = [
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('logout/', custom_logout, name='logout'),
    path('home/', home, name='home'),
    path('test/', test_db, name='test_db'),
]

# django_project/urls.py
