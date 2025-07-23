from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_user, name='register'),
    path('request-otp/', views.request_otp, name='request_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('profile/', views.get_user_profile, name='user_profile'),
    path('logout/', views.logout, name='logout'),
]