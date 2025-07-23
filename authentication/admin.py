from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, OTP, LoginAttempt

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'username', 'is_email_verified', 'is_active', 'created_at']
    list_filter = ['is_email_verified', 'is_active', 'created_at']
    search_fields = ['email', 'username']
    ordering = ['-created_at']

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['user', 'code', 'created_at', 'expires_at', 'is_used', 'attempts']
    list_filter = ['is_used', 'created_at', 'expires_at']
    search_fields = ['user__email', 'code']
    readonly_fields = ['code', 'created_at', 'expires_at']
    ordering = ['-created_at']

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['email', 'ip_address', 'timestamp', 'success']
    list_filter = ['success', 'timestamp']
    search_fields = ['email', 'ip_address']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']