# DotnetAuth API Documentation

## Overview

The DotnetAuth API is a comprehensive authentication and user management solution built with .NET 9.0 and ASP.NET Core. It provides secure user registration, authentication, and account management features with enterprise-grade security.

## 🚀 Quick Start

### Base URL
- **Development**: `http://localhost:5130`
- **Production**: `https://your-domain.com`

### Swagger Documentation
- **Swagger UI**: `{BASE_URL}/swagger`
- **OpenAPI Spec**: `{BASE_URL}/swagger/v1/swagger.json`

## 🔐 Authentication

The API uses **JWT Bearer Token** authentication. Include the token in the Authorization header:

```
Authorization: Bearer {your-jwt-token}
```

### Token Lifecycle
- **Access Token**: 120 minutes (configurable)
- **Refresh Token**: 1 day (normal) / 30 days (remember me)
- **Token Blacklisting**: Supported for secure logout

## 📋 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/register` | Register new user | ❌ |
| POST | `/api/login` | User login | ❌ |
| POST | `/api/verify-otp` | Verify email OTP | ❌ |
| POST | `/api/logout` | User logout | ✅ |
| POST | `/api/forgot-password` | Initiate password reset | ❌ |
| POST | `/api/reset-password` | Reset password | ✅ |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/user` | Get current user | ✅ |
| GET | `/api/user/{id}` | Get user by ID | ✅ |
| DELETE | `/api/user/{id}` | Delete user | ✅ |
| POST | `/api/change-email` | Change email | ✅ |
| POST | `/api/update-phone` | Update phone | ✅ |
| POST | `/api/verify-phone` | Verify phone | ✅ |

### Two-Factor Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/2fa/setup` | Setup 2FA | ✅ |
| POST | `/api/2fa/verify-setup` | Verify 2FA setup | ✅ |
| POST | `/api/2fa/disable` | Disable 2FA | ✅ |
| POST | `/api/two-factor-login` | 2FA login | ❌ |
| GET | `/api/2fa/status` | Get 2FA status | ✅ |

### Activity & History

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/login-history` | Get login history | ✅ |
| GET | `/api/account-activity` | Get account activity | ✅ |

### External Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/external-auth/google` | Google OAuth login | ❌ |
| POST | `/api/external-auth/register` | External auth registration | ❌ |

### Profile Pictures

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/profile-picture/upload` | Upload profile picture | ✅ |
| GET | `/api/profile-picture` | Get profile picture | ✅ |
| DELETE | `/api/profile-picture` | Delete profile picture | ✅ |

## 🛡️ Security Features

### Password Requirements
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- At least 4 unique characters

### Account Security
- **Account Lockout**: 5 failed attempts = 30-minute lockout
- **Email Verification**: Required for account activation
- **CAPTCHA Protection**: Required for registration and login
- **Token Blacklisting**: Secure logout implementation
- **Activity Logging**: All user actions are logged

### Rate Limiting
- Login attempts: 5 per 30 minutes per IP
- Registration: 3 per hour per IP
- OTP requests: 3 per 15 minutes per email

## 📝 Request/Response Examples

### User Registration

**Request:**
```json
POST /api/register
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "MySecureP@ssw0rd123",
  "gender": "Male",
  "role": "Patient",
  "captchaToken": "captcha_token_12345"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Registration successful. Please verify your email with the OTP sent to your email address.",
  "otp": "123456",
  "userId": "user-uuid"
}
```

### User Login

**Request:**
```json
POST /api/login
{
  "email": "john.doe@example.com",
  "password": "MySecureP@ssw0rd123",
  "rememberMe": false,
  "captchaToken": "captcha_token_67890"
}
```

**Response:**
```json
{
  "id": "user-uuid",
  "firstName": "John",
  "lastName": "Doe",
  "fullName": "John Doe",
  "email": "john.doe@example.com",
  "gender": "Male",
  "role": "Patient",
  "isEmailConfirmed": true,
  "createAt": "2024-01-15T10:30:00Z",
  "updateAt": "2024-01-15T10:30:00Z",
  "accessToken": "jwt-token-here",
  "refreshToken": "refresh-token-here"
}
```

## ❌ Error Handling

All errors follow a consistent format:

```json
{
  "titel": "Authentication Error",
  "statusCode": 401,
  "message": "Invalid email or password",
  "errorCode": "AUTH_001",
  "timestamp": "2024-01-15T10:30:00Z",
  "requestId": "req_12345"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| AUTH_001 | Invalid credentials |
| AUTH_002 | Account not verified |
| AUTH_003 | Account locked |
| VAL_001 | Validation error |
| CAPT_001 | CAPTCHA verification failed |

## 🔧 Development Setup

### Prerequisites
- .NET 9.0 SDK
- SQL Server
- Visual Studio 2022 or VS Code

### Configuration

Update `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "your-connection-string"
  },
  "JwtSettings": {
    "validIssuer": "YourAPI",
    "validAudience": "https://localhost:5130",
    "expires": 120,
    "key": "your-32-character-secret-key"
  }
}
```

### Running the API

```bash
dotnet restore
dotnet build
dotnet run
```

## 📊 Monitoring & Logging

- **Application Insights**: Integrated for production monitoring
- **Structured Logging**: Using Serilog with JSON formatting
- **Health Checks**: Available at `/health`
- **Metrics**: Custom metrics for authentication events

## 🧪 Testing

### Swagger UI Testing
1. Navigate to `/swagger`
2. Use the "Authorize" button to set your JWT token
3. Test endpoints directly from the UI

### Postman Collection
Import the OpenAPI specification into Postman for comprehensive testing.

## 📞 Support

For API support and questions:
- **Email**: support@dotnetauth.com
- **Documentation**: This file and Swagger UI
- **Issues**: GitHub Issues (if applicable)

---

**Version**: 1.0  
**Last Updated**: January 2024  
**License**: MIT
