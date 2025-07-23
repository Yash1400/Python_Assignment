TO run the code do the following steps
1. Run git and use the command python manage.py runserver
2. Run postman and do the following steps:
3. Register a User:
   curl -X POST http://localhost:8000/api/register/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'
   Expected output:
   {
    "message": "Registration successful. Please verify your email.",
    "user_id": 1
   }
   
4. Request OTP:
    curl -X POST http://localhost:8000/api/request-otp/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'
   Expected Output on your server terminal:
   ==================================================
📧 EMAIL NOTIFICATION
==================================================
To: test@example.com
Subject: Your OTP for Login
OTP Code: 123456
==================================================

5. Verify OTP:
   curl -X POST http://localhost:8000/api/verify-otp/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "otp": "123456"}'
   Expected Output:
   {
    "message": "Login successful.",
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "email": "test@example.com",
        "username": "test@example.com",
        "is_email_verified": true,
        "created_at": "2024-12-07T10:30:00Z"
    }
}
