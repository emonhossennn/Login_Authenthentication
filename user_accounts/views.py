from django.contrib.auth.views import LogoutView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate, get_user_model
from django.contrib import auth
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from .utils import validate_password
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from .serializers import RegisterSerializer, UserProfileSerializer, UserProfileUpdateSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.crypto import get_random_string
from django.core.cache import cache
from rest_framework import generics

User = get_user_model()

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        # print(f"Login attempt for username: {username}")  
        # print(f"Password length: {len(password) if password else 0}")  
        
        # Check if user exists
        user_exists = User.objects.filter(username=username).exists()
        # print(f"User exists in database: {user_exists}")  
        
        if user_exists:
            user = authenticate(request, username=username, password=password)
            # print(f"Authentication result: {user}")  
            
            if user is not None:
                login(request, user)
                # print(f"Login successful for user: {user.username}") 
                messages.success(request, 'Login successful! Welcome to your dashboard.')
                return redirect('/accounts/home/')  
            else:
                # print(f"Authentication failed for user: {username}")  
                messages.error(request, 'Invalid username or password.')
        else:
            # print(f"User {username} does not exist in database")  
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'user_accounts/login.html')

def custom_logout(request):
    """Custom logout that actually logs the user out and redirects to login page"""
    logout(request)  # Actually log the user out
    messages.success(request, 'You have been logged out successfully!')
    return redirect('login')

class CustomLogoutView(LogoutView):
    def get_next_page(self):
        messages.success(self.request, 'You have been logged out successfully!')
        return reverse('home')  # Redirect to dashboard instead of login

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        # print(f"Registration attempt for username: {username}, email: {email}")
        
        is_valid, error_message = validate_password(password1)
        if not is_valid:
            # print(f"Password validation failed: {error_message}")
            messages.error(request, error_message)
            return redirect('register')

        if password1 != password2:
            # print("Passwords don't match")
            messages.error(request, "Passwords don't match!")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            # print(f"Username {username} already exists")
            messages.error(request, "Username already exists!")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            # print(f"Email {email} already exists")
            messages.error(request, "Email already registered!")
            return redirect('register')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password1)
        # print(f"User {username} created successfully with ID: {user.id}")
        
        # Verify user was created
        created_user = User.objects.filter(username=username).first()
        # if created_user:
        #     print(f"User verification successful: {created_user.username}")
        # else:
        #     print(f"User verification failed for: {username}")
        
        # Don't log the user in automatically, redirect to login page instead
        messages.success(request, 'Registration successful! Please log in to continue.')
        # print(f"Redirecting to login page after registration")
        return redirect('login')
    else:
        return render(request, 'user_accounts/register.html')

@login_required
def home(request):
    # print(f"Home view accessed by user: {request.user.username}")  
    # print(f"User is authenticated: {request.user.is_authenticated}") 
    context = {
        'user': request.user,
    }
    return render(request, 'user_accounts/home.html', context)

def test_db(request):
    """Simple test view to check database functionality"""
    total_users = User.objects.count()
    print(f"Total users in database: {total_users}")  
    
    # List all users
    all_users = User.objects.all()
    for user in all_users:
        print(f"User: {user.username}, Email: {user.email}, ID: {user.id}")  
    
    return render(request, 'user_accounts/test.html', {
        'total_users': total_users,
        'users': all_users
    })



class RegisterAPIView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Registration successful!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class UserProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        serializer = UserProfileUpdateSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Profile updated successfully.'})
        return Response(serializer.errors, status=400)

class PasswordResetRequestAPIView(APIView):
    def post(self, request):
        username = request.data.get('username')
        user = User.objects.filter(username=username).first()
        if not user:
            return Response({'error': 'User not found.'}, status=404)
        token = get_random_string(32)
        cache.set(f'reset_token_{token}', user.pk, timeout=600)  # 10 min
        return Response({'reset_token': token})

class PasswordResetConfirmAPIView(APIView):
    def post(self, request):
        token = request.data.get('reset_token')
        new_password = request.data.get('new_password')
        user_id = cache.get(f'reset_token_{token}')
        if not user_id:
            return Response({'error': 'Invalid or expired token.'}, status=400)
        user = User.objects.get(pk=user_id)
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            return Response({'error': error_message}, status=400)
        user.set_password(new_password)
        user.save()
        cache.delete(f'reset_token_{token}')
        return Response({'message': 'Password reset successful.'})

class ChangePasswordView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    def update(self, request, *args, **kwargs):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        if not user.check_password(old_password):
            return Response({"old_password": "Wrong password."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password updated successfully."})