from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
import re

class CustomLoginView(LoginView):
    template_name = 'user_accounts/login.html'
    
    def get_success_url(self):
        messages.success(self.request, 'Login successful! Welcome to your dashboard.')
        return 'home'

class CustomLogoutView(LogoutView):
    def get_next_page(self):
        messages.success(self.request, 'You have been logged out successfully!')
        return super().get_next_page()

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)"
    return True, ""

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            
            messages.success(request, 'Login successful!')
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'user_accounts/login.html')

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        # Password validation
        is_valid, error_message = validate_password(password1)
        if not is_valid:
            messages.error(request, error_message)
            return redirect('register')

        if password1 != password2:
            messages.error(request, "Passwords don't match!")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered!")
            return redirect('register')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password1)
        # Log the user in
        login(request, user)
        messages.success(request, 'Registration successful! Welcome to your dashboard.')
        return redirect('home')
    else:
        return render(request, 'user_accounts/register.html')

@login_required
def home(request):
    context = {
        'user': request.user,
    }
    return render(request, 'user_accounts/home.html', context)