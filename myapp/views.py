from datetime import datetime, timedelta
import jwt
from django.contrib.auth import *
from django.conf import settings
from django.contrib import admin
from rest_framework import generics, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .utils import *
from .models import *
from .serializers import *



User = get_user_model()


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                api_response(
                    status_code=400,
                    message="Registration failed",
                    error=serializer.errors
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        user = serializer.save()
        warnings = []
        optional_fields = ["gender", "first_name", "last_name", "phone_number", "address", "city", "age"]
        for field in optional_fields:
            if hasattr(user, field) and not getattr(user, field):
                warnings.append(f"{field.replace('_', ' ').capitalize()} is not added. Please update your profile.")

        return Response(
            api_response(
                status_code=201,
                message="User registered successfully",
                userid=str(user.id),  # return UUID
                error=warnings
            ),
            status=status.HTTP_201_CREATED
        )





class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data["username"]

        if SoftDeletedUser.objects.filter(username=username).exists():
            return Response(
                api_response(
                    status_code=403,
                    message="Account deleted",
                    error=["Your account has been deleted and cannot be accessed"]
                ),
                status=status.HTTP_403_FORBIDDEN
            )

        user = authenticate(**serializer.validated_data)
        if not user:
            return Response(
                api_response(
                    status_code=401,
                    message="Invalid credentials",
                    error=["Username or password is incorrect"]
                ),
                status=status.HTTP_401_UNAUTHORIZED
            )

        user_uuid = str(user.id)

        access_token = jwt.encode(
            {"user_id": user_uuid, "exp": datetime.utcnow() + timedelta(days=1)},
            settings.SECRET_KEY,
            algorithm="HS256"
        )

        refresh_token = jwt.encode(
            {"user_id": user_uuid, "exp": datetime.utcnow() + timedelta(days=30)},
            settings.SECRET_KEY,
            algorithm="HS256"
        )

        response_data = api_response(
            status_code=200,
            message=f"Login successful. Welcome {user.username}",
            data=UserSerializer(user).data,
            userid=user_uuid
        )
        response_data["access_token"] = access_token
        response_data["refresh_token"] = refresh_token

        response = Response(response_data, status=status.HTTP_200_OK)
        response.set_cookie(
            "access_token",
            access_token,
            httponly=True,
            max_age=86400,
            samesite='Lax'
        )
        response.set_cookie(
            "refresh_token",
            refresh_token,
            httponly=True,
            max_age=2592000,
            samesite='Lax'
        )

        return response




class ProfileView(APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        user_uuid = get_uuid_from_cookie(request)
        user = User.objects.get(id=user_uuid)

        return Response(
            api_response(
                status_code=200,
                message="Profile fetched successfully",
                data=UserSerializer(user).data,
                userid=user_uuid
            )
        )


BLOCKED_FIELDS = {"email", "username", "password"}


# class ProfileUpdateView(APIView):
#     permission_classes = (AllowAny,)

#     def patch(self, request):
#         user_uuid = get_user_from_token(request)
#         if isinstance(user_uuid, Response):
#             return user_uuid

#         user = User.objects.get(id=user_uuid)
#         blocked = BLOCKED_FIELDS & request.data.keys()
#         if blocked:
#             return Response(
#                 api_response(
#                     status_code=400,
#                     message="Restricted fields cannot be updated",
#                     error=list(blocked)
#                 ),
#                 status=400
#             )

#         serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()

#         return Response(
#             api_response(
#                 status_code=200,
#                 message="Profile updated successfully",
#                 data=UserSerializer(user).data,
#                 userid=str(user.id)
#             )
#         )


class ProfileUpdateView(APIView):
    permission_classes = (AllowAny,)

    def put(self, request):
        user_uuid = get_user_from_token(request)
        if isinstance(user_uuid, Response):
            return user_uuid

        user = User.objects.get(id=user_uuid)
        blocked = BLOCKED_FIELDS & request.data.keys()
        if blocked:
            return Response(
                api_response(
                    status_code=400,
                    message="Restricted fields cannot be updated",
                    error=list(blocked)
                ),
                status=400
            )

        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            api_response(
                status_code=200,
                message="Profile updated successfully",
                data=UserSerializer(user).data,
                userid=str(user.id)
            )
        )





class DeleteUserView(APIView):
    permission_classes = (AllowAny,)

    def delete(self, request):
        user_uuid = get_user_from_token(request)
        if isinstance(user_uuid, Response):
            return user_uuid

        cleanup_expired_soft_deleted_users()

        user = User.objects.filter(id=user_uuid).first()
        if not user:
            return Response(
                api_response(
                    status_code=404,
                    message="User not found"
                ),
                status=status.HTTP_404_NOT_FOUND
            )

        SoftDeletedUser.objects.create(
            user_id=user.id,
            username=user.username,
            email=user.email,
            password=user.password,
            first_name=user.first_name,
            last_name=user.last_name,
            phone_number=user.phone_number,
            address=user.address,
            city=user.city,
            gender=user.gender,
            age=user.age
        )

        user.delete()

        return Response(
            api_response(
                status_code=200,
                message="User deleted successfully (soft delete)"
            ),
            status=status.HTTP_200_OK
        )


class SendRecoveryOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                api_response(
                    status_code=400,
                    message="Email is required"
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        if not SoftDeletedUser.objects.filter(email=email).exists():
            return Response(
                api_response(
                    status_code=404,
                    message="This account does not exist or cannot be recovered"
                ),
                status=status.HTTP_404_NOT_FOUND
            )

        # Prepare response object
        response = Response(
            api_response(
                status_code=200,
                message="OTP sent successfully"
            ),
            status=status.HTTP_200_OK
        )

        send_otp_cookie(email, response)

        return response


class RecoverAccountView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")

        if not email or not otp:
            return Response(
                api_response(
                    status_code=400,
                    message="Email and OTP are required"
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        is_valid, result = verify_otp_cookie(request, email, otp)

        if not is_valid:
            return Response(
                api_response(
                    status_code=400,
                    message=result
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        soft_user = SoftDeletedUser.objects.get(email=email)

        user = User.objects.create_user(
            id=soft_user.user_id,
            username=soft_user.username,
            email=soft_user.email,
            password=None,
            first_name=soft_user.first_name or "",
            last_name=soft_user.last_name or "",
            phone_number=soft_user.phone_number or "",
            address=soft_user.address or "",
            city=soft_user.city or "",
            gender=soft_user.gender,
            age=soft_user.age
        )
        
        if soft_user.password:
            user.password = soft_user.password
            user.save()

        # cleanup
        soft_user.delete()
        
        response = Response(
            api_response(
                data=UserSerializer(user).data,
                status_code=200,
                message="Account recovered successfully"
            ),
            status=status.HTTP_200_OK
        )
        # Clear cookies
        response.delete_cookie("reset_otp")
        response.delete_cookie("reset_email")

        return response


class ForgotPasswordSendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                api_response(
                    status_code=400,
                    message="Email is required"
                ),
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user exists
        if not User.objects.filter(email=email).exists():
             return Response(
                api_response(
                    status_code=404,
                    message="User with this email does not exist"
                ),
                status=status.HTTP_404_NOT_FOUND
            )

        # Prepare response object first to pass to utility
        response = Response(
            api_response(
                status_code=200,
                message="OTP sent successfully",
            ),
            status=status.HTTP_200_OK
        )

        send_forgot_password_otp(email, response)

        return response


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def patch(self, request):
        email_input = request.data.get("email")
        otp_input = request.data.get("otp")
        new_password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if not all([email_input, otp_input, new_password, confirm_password]):
            return Response(
                api_response(
                    status_code=400,
                    message="All fields are required (email, otp, password, confirm_password)"
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        if new_password != confirm_password:
             return Response(
                api_response(
                    status_code=400,
                    message="Passwords do not match"
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        response = Response(status=status.HTTP_200_OK)

        success, message = reset_password_with_cookie_validation(
            request, 
            email_input, 
            otp_input, 
            new_password, 
            response
        )

        if not success:
            return Response(
                api_response(
                    status_code=400,
                    message=message
                ),
                status=status.HTTP_400_BAD_REQUEST
            )

        response.data = api_response(
            status_code=200,
            message=message
        )
        return response