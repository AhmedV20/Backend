using System.ComponentModel.DataAnnotations;
using Swashbuckle.AspNetCore.Annotations;

namespace DotnetAuth.Domain.Contracts
{
    /// <summary>
    /// User roles available in the system
    /// </summary>
    public enum UserRole
    {
        /// <summary>
        /// Administrator with full system access
        /// </summary>
        Admin,
        /// <summary>
        /// Medical doctor with healthcare provider privileges
        /// </summary>
        Doctor,
        /// <summary>
        /// Patient with basic user privileges
        /// </summary>
        Patient
    }

    /// <summary>
    /// Gender options for user profiles
    /// </summary>
    public enum Gender
    {
        /// <summary>
        /// Male gender
        /// </summary>
        Male,
        /// <summary>
        /// Female gender
        /// </summary>
        Female
    }

    /// <summary>
    /// User registration request model
    /// </summary>
    /// <remarks>
    /// Contains all required information for creating a new user account.
    /// Password must meet security requirements and CAPTCHA verification is required.
    /// </remarks>
    public class UserRegisterRequest
    {
        /// <summary>
        /// User's first name
        /// </summary>
        /// <example>John</example>
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
        [SwaggerSchema(Description = "User's first name (2-50 characters)")]
        public string FirstName { get; set; }

        /// <summary>
        /// User's last name
        /// </summary>
        /// <example>Doe</example>
        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
        [SwaggerSchema(Description = "User's last name (2-50 characters)")]
        public string LastName { get; set; }

        /// <summary>
        /// User's email address (will be used as username)
        /// </summary>
        /// <example>john.doe@example.com</example>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [SwaggerSchema(Description = "Valid email address that will serve as the username")]
        public string Email { get; set; }

        /// <summary>
        /// User's password (must meet security requirements)
        /// </summary>
        /// <example>MySecureP@ssw0rd123</example>
        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters long")]
        [SwaggerSchema(Description = "Secure password (min 12 chars, must include uppercase, lowercase, digit, and special character)")]
        public string Password { get; set; }

        /// <summary>
        /// User's gender
        /// </summary>
        /// <example>Male</example>
        [Required(ErrorMessage = "Gender is required")]
        [SwaggerSchema(Description = "User's gender (Male or Female)")]
        public Gender Gender { get; set; }

        /// <summary>
        /// User's role in the system
        /// </summary>
        /// <example>Patient</example>
        [Required(ErrorMessage = "Role is required")]
        [SwaggerSchema(Description = "User role (Doctor or Patient - Admin role cannot be registered via API)")]
        public UserRole Role { get; set; }

        /// <summary>
        /// CAPTCHA verification token
        /// </summary>
        /// <example>captcha_token_12345</example>
        [Required(ErrorMessage = "CAPTCHA token is required")]
        [SwaggerSchema(Description = "CAPTCHA verification token to prevent automated registrations")]
        public string CaptchaToken { get; set; }

        public bool IsValidRegistrationRole()
        {
            return Role == UserRole.Doctor || Role == UserRole.Patient;
        }
    }

    public class UserRegisterResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Otp { get; set; }
        public string UserId { get; set; }
    }

    public class VerifyOtpRequest
    {
        public string Email { get; set; }
        public string Otp { get; set; }
    }

    public class VerifyOtpResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string AccessToken { get; set; }
        public string UserId { get; set; }
    }

    public class UserResponse
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Gender { get; set; }
        public string Role { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }

    /// <summary>
    /// User login request model
    /// </summary>
    /// <remarks>
    /// Contains credentials and options for user authentication.
    /// CAPTCHA verification is required to prevent brute force attacks.
    /// </remarks>
    public class UserLoginRequest
    {
        /// <summary>
        /// User's email address
        /// </summary>
        /// <example>john.doe@example.com</example>
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [SwaggerSchema(Description = "Registered email address")]
        public string Email { get; set; }

        /// <summary>
        /// User's password
        /// </summary>
        /// <example>MySecureP@ssw0rd123</example>
        [Required(ErrorMessage = "Password is required")]
        [SwaggerSchema(Description = "User's password")]
        public string Password { get; set; }

        /// <summary>
        /// Whether to extend the session duration
        /// </summary>
        /// <example>false</example>
        [SwaggerSchema(Description = "If true, refresh token will be valid for 30 days instead of 1 day")]
        public bool RememberMe { get; set; }

        /// <summary>
        /// CAPTCHA verification token
        /// </summary>
        /// <example>captcha_token_67890</example>
        [Required(ErrorMessage = "CAPTCHA token is required")]
        [SwaggerSchema(Description = "CAPTCHA verification token to prevent automated login attempts")]
        public string CaptchaToken { get; set; }
    }

    public class CurrentUserResponse
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Gender { get; set; }
        public string Role { get; set; }
        public bool IsEmailConfirmed { get; set; }
        public DateTime CreateAt { get; set; }
        public DateTime UpdateAt { get; set; }
        public string? AccessToken { get; set; }
    }

    public class UpdateUserRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public Gender Gender { get; set; }
    }

    public class RevokeRefreshTokenResponse
    {
        public string Message { get; set; }
    }

    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }


    public class Setup2faRequest
    {
        public string TwoFactorType { get; set; }
    }

    public class Setup2faResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Secret { get; set; }
        public string QrCodeUrl { get; set; }
        public string VerificationCode { get; set; }
    }

    public class Verify2faSetupRequest
    {
        public string VerificationCode { get; set; }
    }

    public class Verify2faSetupResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public List<string> RecoveryCodes { get; set; }
    }

    public class Disable2faRequest
    {
        public string Password { get; set; }
    }

    public class Disable2faResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }

    public class TwoFactorLoginRequest
    {
        public string Email { get; set; }
        public string TwoFactorCode { get; set; }
        public bool RememberDevice { get; set; }
    }

    public class TwoFactorLoginResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public string TwoFactorType { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string UserId { get; set; }
        public string Email { get; set; }
    }
}