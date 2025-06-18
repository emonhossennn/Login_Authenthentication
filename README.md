# Django Authentication Project

A Django web application with user authentication features including login, registration, and dashboard.

## Features

- User Registration with email
- User Login/Logout
- Password validation (8+ chars, uppercase, lowercase, number, special character)
- Protected Dashboard
- Bootstrap UI
- Form validation (client-side and server-side)

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd login
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
```bash
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Create a superuser (optional):
```bash
python manage.py createsuperuser
```

7. Run the development server:
```bash
python manage.py runserver
```

## Usage

- Visit `http://127.0.0.1:8000/` to access the application
- Register a new account at `/accounts/register/`
- Login at `/accounts/login/`
- Access your dashboard at `/accounts/home/`

## Project Structure

```
login/
├── auth_project/          # Main project settings
├── user_accounts/         # Authentication app
├── templates/             # HTML templates
│   ├── base.html
│   └── user_accounts/
│       ├── login.html
│       ├── register.html
│       └── home.html
├── manage.py
├── requirements.txt
└── README.md
```

## Password Requirements

Passwords must contain:
- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*(),.?":{}|<>)

## Technologies Used

- Django 5.2.3
- Python 3.x
- Bootstrap 5
- SQLite (development database) 