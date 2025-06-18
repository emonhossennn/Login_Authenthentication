from django.urls import path
from .views import CustomLoginView, CustomLogoutView, register, home

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='login'),
    path('register/', register, name='register'),
    path('logout/', CustomLogoutView.as_view(next_page='login'), name='logout'),
    path('home/', home, name='home'),
]

# django_project/urls.py
