import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.db import models
from django.utils import timezone
from datetime import timedelta



class RecoveryOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=4)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at
#model.py for custom user model with soft delete functionality

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")

        email = self.normalize_email(email)
        user = self.model(
            username=username,
            email=email,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_active", True)

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractBaseUser):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )

    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]

    username = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    phone_number = models.CharField(max_length=10, blank=True)
    address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=50, blank=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, null=True, blank=True)
    age = models.IntegerField(blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = CustomUserManager()  

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        return self.is_admin
    


class SoftDeletedUser(models.Model):
    user_id = models.UUIDField()
    username = models.CharField(max_length=30)
    email = models.EmailField()
    password = models.CharField(max_length=255, null=True, blank=True)
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    phone_number = models.CharField(max_length=10, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=50, blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    age = models.IntegerField(blank=True, null=True)
    deleted_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.username} (deleted)"

