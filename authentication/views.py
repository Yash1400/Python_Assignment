from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from django_ratelimit.decorators import ratelimit
from django.views.decorators.cache import never_cache

from .models import OTP, LoginAttempt
from .serializers import (
    UserRegistrationSerializer, 
    OTPRequestSerializer, 
    OTPVerificationSerializer,
    UserSerializer
)
from .utils import generate_jwt_token, send_otp_email, get_client_ip

import logging

User = get_user_model()
logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
@never_cache
def register_user(request):
    """
    Register a new user with email validation
    """
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    is_email_verified=False
                )
                
                logger.info(f"New user registered: {email}")
                
                return Response({
                    'message': 'Registration successful. Please verify your email.',
                    'user_id': user.id
                }, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            logger.error(f"Registration error for {email}: {str(e)}")
            return Response({
                'error': 'Registration failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@never_cache
def request_otp(request):
    """
    Generate and send OTP to user's email
    """
    serializer = OTPRequestSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            
            # Invalidate all previous OTPs for this user
            OTP.objects.filter(user=user, is_used=False).update(is_used=True)
            
            # Create new OTP
            with transaction.atomic():
                otp = OTP.objects.create(user=user)
                send_otp_email(user, otp.code)
                
                logger.info(f"OTP generated for user: {email}")
                
                return Response({
                    'message': 'OTP sent to your email.',
                    'expires_in_minutes': 5
                }, status=status.HTTP_200_OK)
                
        except User.DoesNotExist:
            return Response({
                'error': 'No user found with this email address.'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"OTP request error for {email}: {str(e)}")
            return Response({
                'error': 'Failed to send OTP. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@never_cache
def verify_otp(request):
    """
    Verify OTP and return JWT token on success
    """
    serializer = OTPVerificationSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp']
        client_ip = get_client_ip(request)
        
        try:
            user = User.objects.get(email=email)
            
            # Get the most recent valid OTP
            otp = OTP.objects.filter(
                user=user,
                code=otp_code,
                is_used=False
            ).first()
            
            # Log login attempt
            login_attempt = LoginAttempt.objects.create(
                email=email,
                ip_address=client_ip,
                success=False
            )
            
            if not otp:
                logger.warning(f"Invalid OTP attempt for {email} from {client_ip}")
                return Response({
                    'error': 'Invalid OTP code.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Increment attempts
            otp.attempts += 1
            otp.save()
            
            if not otp.is_valid():
                if otp.attempts >= 3:
                    otp.is_used = True
                    otp.save()
                    logger.warning(f"OTP attempts exceeded for {email}")
                    return Response({
                        'error': 'OTP has expired or exceeded maximum attempts.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif timezone.now() > otp.expires_at:
                    logger.warning(f"Expired OTP attempt for {email}")
                    return Response({
                        'error': 'OTP has expired.'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # OTP is valid - mark as used and create session
            with transaction.atomic():
                otp.is_used = True
                otp.save()
                
                user.is_email_verified = True
                user.save()
                
                # Update login attempt as successful
                login_attempt.success = True
                login_attempt.save()
                
                # Generate JWT token
                token = generate_jwt_token(user)
                
                logger.info(f"Successful login for {email} from {client_ip}")
                
                return Response({
                    'message': 'Login successful.',
                    'token': token,
                    'user': UserSerializer(user).data
                }, status=status.HTTP_200_OK)
                
        except User.DoesNotExist:
            logger.warning(f"Login attempt for non-existent user: {email}")
            return Response({
                'error': 'Invalid credentials.'
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error(f"OTP verification error for {email}: {str(e)}")
            return Response({
                'error': 'Verification failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def get_user_profile(request):
    """
    Get authenticated user's profile
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['POST'])
def logout(request):
    """
    Logout user (client should discard the token)
    """
    logger.info(f"User {request.user.email} logged out")
    return Response({
        'message': 'Logged out successfully.'
    }, status=status.HTTP_200_OK)