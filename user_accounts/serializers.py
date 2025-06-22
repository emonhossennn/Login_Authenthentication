from rest_framework import serializers
from django.contrib.auth import get_user_model
from .utils import validate_password
from accounts.models import CustomUser
import django

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    user_type = serializers.ChoiceField(choices=CustomUser.USER_TYPE_CHOICES)
    profile_name = serializers.CharField(required=True)
    phone = serializers.CharField(required=False)
    date_of_birth = serializers.DateField(required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'profile_name', 'phone', 'date_of_birth', 'user_type']

    def validate(self, data):
        is_valid, error_message = validate_password(data['password'])
        if not is_valid:
            raise serializers.ValidationError(error_message)
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError("Username already exists.")
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError("Email already registered.")
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            profile_name=validated_data.get('profile_name', ''),
            phone=validated_data.get('phone', ''),
            date_of_birth=validated_data.get('date_of_birth', None),
            user_type=validated_data.get('user_type', 'customer'),
        )
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    mobile_no = serializers.CharField(source='phone')
    class Meta:
        model = CustomUser
        fields = ['full_name', 'mobile_no', 'date_of_birth', 'user_type']
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.profile_name

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['date_of_birth', 'phone']


