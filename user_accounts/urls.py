from django.urls import path
from .views import (
    login_view, custom_logout, register, home, test_db,
    RegisterAPIView, UserProfileAPIView, LogoutAPIView,
    PasswordResetRequestAPIView, PasswordResetConfirmAPIView,
    UserProfileUpdateAPIView, ChangePasswordView
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    # Web views
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('logout/', custom_logout, name='logout'),
    path('home/', home, name='home'),
    path('test/', test_db, name='test_db'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),

    # API endpoints
    path('api/register/', RegisterAPIView.as_view(), name='api-register'),
    path('api/login/', TokenObtainPairView.as_view(), name='api-login'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/profile/', UserProfileAPIView.as_view(), name='api-profile'),
    path('api/logout/', LogoutAPIView.as_view(), name='api-logout'),
    path('api/password-reset/request/', PasswordResetRequestAPIView.as_view(), name='api-password-reset-request'),
    path('api/password-reset/confirm/', PasswordResetConfirmAPIView.as_view(), name='api-password-reset-confirm'),
    path('api/profile/update/', UserProfileUpdateAPIView.as_view(), name='api-profile-update'),
]