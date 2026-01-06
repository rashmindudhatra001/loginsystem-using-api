from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from .models import SoftDeletedUser


User = get_user_model()



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'first_name', 'last_name',
            'email', 'phone_number', 'address',
            'city', 'gender', 'age'
        ]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    age = serializers.IntegerField(required=False)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    address = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    gender = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = [
            'username', 'email',
            'first_name', 'last_name',
            'phone_number', 'gender', 'age',
            'address', 'city',
            'password', 'confirm_password'
        ]

    def validate(self, attrs):
        username = attrs.get("username")
        email = attrs.get("email")

        if SoftDeletedUser.objects.filter(username=username).exists() or \
           SoftDeletedUser.objects.filter(email=email).exists():
            raise serializers.ValidationError({
                "detail": "This account was deleted. You can recover your account instead."
            })

        errors = {}

        if User.objects.filter(username=username).exists():
            errors.setdefault("username", []).append(
                "custom user with this username already exists."
            )

        if User.objects.filter(email=email).exists():
            errors.setdefault("email", []).append(
                "custom user with this email already exists."
            )

        if errors:
            raise serializers.ValidationError(errors)

        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError({
                "confirm_password": ["Passwords do not match"]
            })

        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        return User.objects.create_user(**validated_data)




class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)




class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'first_name',
            'last_name',
            'phone_number',
            'address',
            'city',
            'gender',
            'age',
        ]




def validate(self, attrs):
    username = attrs.get("username")
    email = attrs.get("email")

    errors = {}

    if (
        (username and SoftDeletedUser.objects.filter(username=username).exists()) or
        (email and SoftDeletedUser.objects.filter(email=email).exists())
    ):
        raise serializers.ValidationError({
            "detail": "This account was deleted. You can recover your account instead."
        })

    if username and User.objects.filter(username=username).exists():
        errors.setdefault("username", []).append(
            "custom user with this username already exists."
        )

    if email and User.objects.filter(email=email).exists():
        errors.setdefault("email", []).append(
            "custom user with this email already exists."
        )

    if errors:
        raise serializers.ValidationError(errors)

    password = attrs.get("password")
    confirm_password = attrs.get("confirm_password")

    if password or confirm_password:
        if password != confirm_password:
            raise serializers.ValidationError({
                "confirm_password": ["Passwords do not match"]
            })

    return attrs

