"""
URL configuration for base project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from myapp.views import *
from django.conf import settings
from rest_framework_simplejwt.views import (
    TokenObtainPairView,    
    TokenRefreshView,
)
from myapp.views import (
    RegisterView,
    LoginView,
    RecoverAccountView,  
    SendRecoveryOTPView,  
    ProfileView,
    ProfileUpdateView,
    DeleteUserView
)

urlpatterns = [
    path('admin/', admin.site.urls),

    # AUTH
    path('api/auth/register/', RegisterView.as_view(), name='auth_register'),
    path('api/auth/login/', LoginView.as_view(), name='auth_login'),

    # PROFILE
    path("api/profile/", ProfileView.as_view()),
    path("api/profile/update/", ProfileUpdateView.as_view()),

    # DELETE (SOFT DELETE)
    path("delete/", DeleteUserView.as_view(), name="delete-user"),

    #  ACCOUNT RECOVERY
    path("api/auth/recovery/send-otp/", SendRecoveryOTPView.as_view(), name="send-recovery-otp"),
    path("api/auth/recovery/confirm/", RecoverAccountView.as_view(), name="recover-account"),

    # FORGOT PASSWORD
    path("api/auth/forgot-password/send-otp/", ForgotPasswordSendOTPView.as_view(), name="forgot-password-send-otp"),
    path("api/auth/forgot-password/reset/", ResetPasswordView.as_view(), name="forgot-password-reset"),



    # JWT (OPTIONAL – you can remove if unused)
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
