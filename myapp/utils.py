import datetime
from random import random
import jwt
import uuid
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from .models import *
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
import smtplib
from django.core.mail import send_mail



User = get_user_model()# Utility Functions





from datetime import datetime, timedelta

from datetime import datetime, timedelta
import jwt
from django.conf import settings

def generate_jwt(user_id, days_valid=1):
    """
    Generate a JWT token for a given user ID.
    """
    payload = {
        "user_id": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=days_valid)
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    
    # PyJWT >= 2 returns str, <2 returns bytes, so decode if necessary
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    
    return token


def get_user_from_cookie(request):
    token = request.COOKIES.get("access_token")
    if not token:
        raise AuthenticationFailed("Authentication required.")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("user_id")
        if not user_id:
            raise AuthenticationFailed("Invalid token payload.")
        uuid.UUID(str(user_id))
        user = User.objects.filter(id=user_id).first()
        if not user:
            raise AuthenticationFailed("User not found.")
        if not user.is_active:
            raise AuthenticationFailed("Account disabled.")
        return user
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Token expired.")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid token.")







def get_otp_from_cookie(request):# Retrieve OTP and email from signed cookies
   
    try:# Retrieve signed cookies
        otp = request.get_signed_cookie("reset_otp")
        email = request.get_signed_cookie("reset_email")
        return otp, email
    except Exception:
        return None


def api_response(# Standardized API response format 
    status_code,
    message,
    data=None,
    userid=None,
    acssestokan=None,
    refresh=None,
    error=None
):
    return {#   Response dictionary structure
        "status_code": status_code,
        "message": message,
        "data": data or {},
        "uuid": userid,
        "error": error or []
    }

def get_uuid_from_cookie(request):  # Extract and validate user UUID from JWT in cookies

    token = request.COOKIES.get("access_token")
    if not token:
        raise AuthenticationFailed("Authentication token not found.")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Token expired.")
    except jwt.InvalidTokenError:
        raise AuthenticationFailed("Invalid token.")

    user_uuid = payload.get("user_id")
    if not user_uuid:
        raise AuthenticationFailed("JWT payload missing 'user_id'.")

    # Validate that it's a valid UUID
    try:
        uuid.UUID(str(user_uuid))
    except ValueError:
        raise AuthenticationFailed("Invalid user ID format in token. Please log in again.")

    return str(user_uuid)

def get_user_from_token(request):
   
    token = request.COOKIES.get("access_token")

    if not token:
        return Response(
            api_response(
                status_code=401,
                message="Authentication required",
                error=["Access token not found"]
            ),
            status=status.HTTP_401_UNAUTHORIZED
        )

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )

        user_id = payload.get("user_id")
        if not user_id:
            return Response(
                api_response(
                    status_code=401,
                    message="Invalid token payload",
                    error=["user_id missing in token"]
                ),
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Validate UUID format
        try:
            uuid.UUID(str(user_id))
        except ValueError:
            return Response(
                api_response(
                    status_code=401,
                    message="Invalid token payload",
                    error=["Invalid user ID format. Please log in again."]
                ),
                status=status.HTTP_401_UNAUTHORIZED
            )

        
        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response(
                api_response(
                    status_code=404,
                    message="User not found",
                    error=["User associated with this token does not exist"]
                ),
                status=status.HTTP_404_NOT_FOUND
            )

        if not user.is_active:
            return Response(
                api_response(
                    status_code=403,
                    message="Account disabled",
                    error=["User account is inactive"]
                ),
                status=status.HTTP_403_FORBIDDEN
            )

        return str(user_id)

    except jwt.ExpiredSignatureError:
        return Response(
            api_response(
                status_code=401,
                message="Token expired",
                error=["Access token has expired"]
            ),
            status=status.HTTP_401_UNAUTHORIZED
        )

    except jwt.InvalidTokenError:
        return Response(
            api_response(
                status_code=401,
                message="Invalid token",
                error=["Token is invalid or tampered"]
            ),
            status=status.HTTP_401_UNAUTHORIZED
        )

    except Exception as e:
        return Response(
            api_response(
                status_code=500,
                message="Internal server error",
                error=[str(e)]
            ),
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )







def cleanup_expired_soft_deleted_users():

    expiry_time = timezone.now() - datetime.timedelta(days=30)
    SoftDeletedUser.objects.filter(deleted_at__lt=expiry_time).delete()



def generate_recovery_otp(email, expiry_minutes=2):

    # delete old OTP
    RecoveryOTP.objects.filter(email=email).delete()

    otp = str(secrets.randbelow(9000) + 1000)
    expires_at = timezone.now() + datetime.timedelta(minutes=expiry_minutes)

    RecoveryOTP.objects.create(
        email=email,
        otp=otp,
        expires_at=expires_at
    )

    print(f"[RECOVERY OTP] {email} => {otp}")
    return otp



def verify_recovery_otp(email, user_otp):
    try:
        otp_obj = RecoveryOTP.objects.get(email=email)
    except RecoveryOTP.DoesNotExist:
        return False, "OTP not found or expired"

    if timezone.now() > otp_obj.expires_at:
        otp_obj.delete()
        return False, "OTP expired"

    if otp_obj.otp != str(user_otp):  
        return False, "Invalid OTP"

    return True, otp_obj



def send_forgot_password_otp(email, response, expiry_seconds=150):

    otp = str(secrets.randbelow(9000) + 1000)

    # Send Email
    send_mail(
        subject="Password Reset OTP",
        message=(
            f"Your password reset OTP is: {otp}\n\n"
            f"This OTP is valid for {expiry_seconds // 2.5} minutes."
        ),
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[email],
        fail_silently=False,
    )

    # Store OTP in signed cookies
    response.set_signed_cookie(
        "reset_otp",
        otp,
        max_age=expiry_seconds,
        salt=settings.SECRET_KEY,
        httponly=True,
        samesite="Lax"
    )
    response.set_signed_cookie(
        "reset_email",
        email,
        max_age=expiry_seconds,
        salt=settings.SECRET_KEY,
        httponly=True,
        samesite="Lax"
    )

    return True


def verify_otp_cookie(request, email_input, otp_input):
    # Retrieve cookies
    try:
        cookie_otp = request.get_signed_cookie("reset_otp", salt=settings.SECRET_KEY)
        cookie_email = request.get_signed_cookie("reset_email", salt=settings.SECRET_KEY)
    except Exception:
        return False, "OTP is expired or invalid"

    # Validate data
    if str(otp_input) != str(cookie_otp) or email_input != cookie_email:
        return False, "Invalid OTP or email mismatch"
    
    return True, "Valid"

def reset_password_with_cookie_validation(request, email_input, otp_input, new_password, response):
 
    is_valid, msg = verify_otp_cookie(request, email_input, otp_input)
    if not is_valid:
        return False, msg

    # Change Password
    try:
        user = User.objects.get(email=email_input)
        user.set_password(new_password)
        user.save()
    except User.DoesNotExist:
        return False, "User not found"

    # Clear Cookies
    response.delete_cookie("reset_otp")
    response.delete_cookie("reset_email")
    
    return True, "Password reset successfully"

def send_otp_cookie(email, response, expiry_seconds=150):
    otp = str(secrets.randbelow(9000) + 1000)
    
    # Print to terminal
    print(f"\n[OTP] Code for {email}: {otp}\n")

    response.set_signed_cookie(
        "reset_otp",
        otp,
        max_age=expiry_seconds,
        salt=settings.SECRET_KEY,
        httponly=True,
        samesite="Lax"
    )

    response.set_signed_cookie(
        "reset_email",
        email,
        max_age=expiry_seconds,
        salt=settings.SECRET_KEY,
        httponly=True,
        samesite="Lax"
    )

    return True




