from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('seller', 'Seller'),
        ('customer', 'Customer'),
        
    )

    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='regular')
    profile_name = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)

    # Add extra fields here if needed
    phone = models.CharField(max_length=20, blank=True)
