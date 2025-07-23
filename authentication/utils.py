import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.core.mail import send_mail
from django.template.loader import render_to_string
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            return (user, token)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),
        'iat': datetime.utcnow(),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')

def send_otp_email(user, otp_code):
    """
    Mock email sending function - prints to console instead of sending actual email
    """
    subject = 'Your OTP for Login'
    message = f"""
    Hi {user.email},
    
    Your OTP for login is: {otp_code}
    
    This OTP is valid for 5 minutes only.
    
    If you didn't request this OTP, please ignore this email.
    
    Best regards,
    Your App Team
    """
    
    # In production, you would use actual email sending
    # send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
    
    # Mock email - print to console
    print("=" * 50)
    print("📧 EMAIL NOTIFICATION")
    print("=" * 50)
    print(f"To: {user.email}")
    print(f"Subject: {subject}")
    print(f"OTP Code: {otp_code}")
    print("=" * 50)
    
    logger.info(f"OTP {otp_code} sent to {user.email}")

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip