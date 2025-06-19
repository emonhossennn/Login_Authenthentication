from django.contrib.auth.views import LogoutView
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse
import re

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f"Login attempt for username: {username}")  
        print(f"Password length: {len(password) if password else 0}")  
        
        # Check if user exists
        user_exists = User.objects.filter(username=username).exists()
        print(f"User exists in database: {user_exists}")  
        
        if user_exists:
            user = authenticate(request, username=username, password=password)
            print(f"Authentication result: {user}")  
            
            if user is not None:
                login(request, user)
                print(f"Login successful for user: {user.username}") 
                messages.success(request, 'Login successful! Welcome to your dashboard.')
                return redirect('/accounts/home/')  
            else:
                print(f"Authentication failed for user: {username}")  
                messages.error(request, 'Invalid username or password.')
        else:
            print(f"User {username} does not exist in database")  
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

def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        print(f"Registration attempt for username: {username}, email: {email}")  # Debug print

        # Password validation
        is_valid, error_message = validate_password(password1)
        if not is_valid:
            print(f"Password validation failed: {error_message}")  # Debug print
            messages.error(request, error_message)
            return redirect('register')

        if password1 != password2:
            print("Passwords don't match")  # Debug print
            messages.error(request, "Passwords don't match!")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            print(f"Username {username} already exists")  # Debug print
            messages.error(request, "Username already exists!")
            return redirect('register')

        if User.objects.filter(email=email).exists():
            print(f"Email {email} already exists")  # Debug print
            messages.error(request, "Email already registered!")
            return redirect('register')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password1)
        print(f"User {username} created successfully with ID: {user.id}")  # Debug print
        
        # Verify user was created
        created_user = User.objects.filter(username=username).first()
        if created_user:
            print(f"User verification successful: {created_user.username}")  # Debug print
        else:
            print(f"User verification failed for: {username}")  # Debug print
        
        # Don't log the user in automatically, redirect to login page instead
        messages.success(request, 'Registration successful! Please log in to continue.')
        print(f"Redirecting to login page after registration")  # Debug print
        return redirect('login')
    else:
        return render(request, 'user_accounts/register.html')

@login_required
def home(request):
    print(f"Home view accessed by user: {request.user.username}")  
    print(f"User is authenticated: {request.user.is_authenticated}") 
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