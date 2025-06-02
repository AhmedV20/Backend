using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace DotnetAuth.Controllers
{
    /// <summary>
    /// Authentication and User Management Controller
    /// </summary>
    /// <remarks>
    /// This controller handles all authentication-related operations including:
    /// - User registration and email verification
    /// - User login and logout
    /// - Password management (forgot/reset)
    /// - Account management (email/phone updates)
    /// - User profile operations
    /// - Activity tracking and login history
    /// </remarks>
    [Route("api/")]
    [ApiController]
    [SwaggerTag("Authentication and User Management")]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly IUserServices _userService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthController> _logger;
        private readonly IActivityLoggingService _activityLoggingService;
        private readonly ICurrentUserService _currentUserService;
        private readonly ITwoFactorService _twoFactorService;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthController(
            IUserServices userService,
            ITokenService tokenService,
            ILogger<AuthController> logger,
            IActivityLoggingService activityLoggingService,
            ICurrentUserService currentUserService,
            ITwoFactorService twoFactorService,
            UserManager<ApplicationUser> userManager)
        {
            _userService = userService;
            _tokenService = tokenService;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
            _currentUserService = currentUserService;
            _twoFactorService = twoFactorService;
            _userManager = userManager;
        }

        /// <summary>
        /// Register a new user account
        /// </summary>
        /// <remarks>
        /// Creates a new user account with the provided information. The user will receive an OTP via email for verification.
        ///
        /// **Registration Process:**
        /// 1. Validates the registration data and CAPTCHA
        /// 2. Creates the user account with unverified status
        /// 3. Generates and sends an OTP to the provided email
        /// 4. Assigns a default profile picture
        /// 5. Adds the user to the specified role
        ///
        /// **Password Requirements:**
        /// - Minimum 12 characters
        /// - At least one uppercase letter
        /// - At least one lowercase letter
        /// - At least one digit
        /// - At least one special character
        /// - At least 4 unique characters
        ///
        /// **Valid Roles:** Doctor, Patient (Admin role cannot be registered via this endpoint)
        /// </remarks>
        /// <param name="request">User registration data including personal information, credentials, and CAPTCHA token</param>
        /// <returns>Registration result with success status and OTP for email verification</returns>
        /// <response code="200">Registration successful - OTP sent to email</response>
        /// <response code="400">Invalid registration data, weak password, or CAPTCHA verification failed</response>
        /// <response code="409">User with this email already exists</response>
        /// <response code="500">Internal server error during registration process</response>
        [HttpPost("register")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Register a new user account",
            Description = "Creates a new user account and sends email verification OTP",
            OperationId = "RegisterUser",
            Tags = new[] { "Authentication" }
        )]
        [SwaggerResponse(200, "Registration successful", typeof(UserRegisterResponse))]
        [SwaggerResponse(400, "Invalid request data", typeof(ErrorResponse))]
        [SwaggerResponse(409, "User already exists", typeof(ErrorResponse))]
        [SwaggerResponse(500, "Internal server error", typeof(ErrorResponse))]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            var response = await _userService.RegisterAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Registration",
                    "New user registration completed");
            }
            return Ok(response);
        }

        /// <summary>
        /// Authenticate user and generate access tokens
        /// </summary>
        /// <remarks>
        /// Authenticates a user with email and password, returning JWT tokens for API access.
        ///
        /// **Login Process:**
        /// 1. Validates email and password credentials
        /// 2. Verifies CAPTCHA token
        /// 3. Checks if account is verified and not locked
        /// 4. Generates JWT access token and refresh token
        /// 5. Logs the login activity
        ///
        /// **Two-Factor Authentication:**
        /// If 2FA is enabled, this endpoint will return `RequiresTwoFactor: true` and you must use the `/api/two-factor-login` endpoint to complete authentication.
        ///
        /// **Remember Me:**
        /// - When enabled: Refresh token valid for 30 days
        /// - When disabled: Refresh token valid for 1 day
        ///
        /// **Account Lockout:**
        /// After 5 failed attempts, the account will be locked for 30 minutes.
        /// </remarks>
        /// <param name="request">Login credentials including email, password, CAPTCHA token, and remember me option</param>
        /// <returns>User information with JWT tokens or two-factor authentication requirement</returns>
        /// <response code="200">Login successful - returns user data and tokens</response>
        /// <response code="400">Invalid credentials, unverified account, or CAPTCHA verification failed</response>
        /// <response code="401">Authentication failed - invalid email or password</response>
        /// <response code="423">Account is locked due to too many failed attempts</response>
        /// <response code="500">Internal server error during authentication</response>
        [HttpPost("login")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Authenticate user and generate access tokens",
            Description = "Validates user credentials and returns JWT tokens for API access",
            OperationId = "LoginUser",
            Tags = new[] { "Authentication" }
        )]
        [SwaggerResponse(200, "Login successful", typeof(UserResponse))]
        [SwaggerResponse(400, "Invalid request or unverified account", typeof(ErrorResponse))]
        [SwaggerResponse(401, "Authentication failed", typeof(ErrorResponse))]
        [SwaggerResponse(423, "Account locked", typeof(ErrorResponse))]
        [SwaggerResponse(500, "Internal server error", typeof(ErrorResponse))]
        public async Task<ActionResult<UserResponse>> Login([FromBody] UserLoginRequest request)
        {
            try
            {
                var response = await _userService.LoginAsync(request);
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Verify email address using OTP
        /// </summary>
        /// <remarks>
        /// Verifies the user's email address using the OTP sent during registration.
        ///
        /// **Verification Process:**
        /// 1. Validates the provided OTP against the stored value
        /// 2. Checks if the OTP has not expired (15-minute validity)
        /// 3. Marks the email as verified
        /// 4. Generates JWT access token for the verified user
        /// 5. Logs the verification activity
        ///
        /// **OTP Expiry:**
        /// OTPs are valid for 15 minutes from the time they are generated.
        ///
        /// **After Verification:**
        /// The user account becomes fully active and can be used for login.
        /// </remarks>
        /// <param name="request">Email and OTP for verification</param>
        /// <returns>Verification result with access token if successful</returns>
        /// <response code="200">Email verified successfully - returns access token</response>
        /// <response code="400">Invalid or expired OTP</response>
        /// <response code="404">User not found or already verified</response>
        /// <response code="500">Internal server error during verification</response>
        [HttpPost("verify-otp")]
        [AllowAnonymous]
        [SwaggerOperation(
            Summary = "Verify email address using OTP",
            Description = "Confirms user email address with the OTP sent during registration",
            OperationId = "VerifyEmailOtp",
            Tags = new[] { "Authentication" }
        )]
        [SwaggerResponse(200, "Email verified successfully", typeof(VerifyOtpResponse))]
        [SwaggerResponse(400, "Invalid or expired OTP", typeof(ErrorResponse))]
        [SwaggerResponse(404, "User not found", typeof(ErrorResponse))]
        [SwaggerResponse(500, "Internal server error", typeof(ErrorResponse))]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
        {
            var response = await _userService.VerifyOtpAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Email Verification",
                    "Email verified successfully");
            }
            return Ok(response);
        }

        [HttpPost("two-factor-login")]
        [AllowAnonymous]
        public async Task<ActionResult<TwoFactorLoginResponse>> TwoFactorLogin([FromBody] TwoFactorLoginRequest request)
        {
            try
            {
                var response = await _twoFactorService.VerifyTwoFactorLoginAsync(request);
                if (response.Success)
                {
                    // Find the user to log activity
                    var user = await _userManager.FindByEmailAsync(request.Email);
                    if (user != null)
                    {
                        await _activityLoggingService.LogActivityAsync(
                            user.Id,
                            "Two-Factor Authentication",
                            "Successfully authenticated with two-factor authentication");
                    }
                }
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during two-factor login");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var response = await _userService.ForgotPasswordAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    response.UserId,
                    "Password Reset Initiated",
                    "Password reset process initiated");
            }
            return Ok(response);
        }

        [HttpPost("reset-password")]
        [Authorize]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var response = await _userService.ResetPasswordAsync(request);
            var userId = _currentUserService.GetUserId();
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Password Reset Complete",
                    "Password was successfully reset");
            }
            return Ok(response);
        }

        [HttpPost("change-email")]
        [Authorize]
        public async Task<IActionResult> ChangeEmail([FromBody] ChangeEmailRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.ChangeEmailAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Email Change Initiated",
                    $"Email change requested to: {request.NewEmail}");
            }
            return Ok(response);
        }

        [HttpPost("update-phone")]
        [Authorize]
        public async Task<ActionResult<UpdatePhoneNumberResponse>> UpdatePhoneNumber([FromBody] UpdatePhoneNumberRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.UpdatePhoneNumberAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Phone Update Initiated",
                    $"Phone number update requested to: {request.PhoneNumber}");
            }
            return Ok(response);
        }

        [HttpPost("verify-phone")]
        [Authorize]
        public async Task<ActionResult<VerifyPhoneNumberResponse>> VerifyPhoneNumber([FromBody] VerifyPhoneNumberRequest request)
        {
            var userId = _currentUserService.GetUserId();
            var response = await _userService.VerifyPhoneNumberAsync(request);
            if (response.Success)
            {
                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "Phone Verification",
                    $"Phone number verified: {request.PhoneNumber}");
            }
            return Ok(response);
        }

        /// <summary>
        /// Get current authenticated user's profile information
        /// </summary>
        /// <remarks>
        /// Retrieves the complete profile information for the currently authenticated user.
        ///
        /// **Returned Information:**
        /// - User ID and basic profile data (name, email, gender)
        /// - Account status (email verification, creation/update dates)
        /// - User role (Admin, Doctor, Patient)
        /// - Current access token
        ///
        /// **Authentication Required:**
        /// This endpoint requires a valid JWT token in the Authorization header.
        ///
        /// **Activity Logging:**
        /// This action is logged as "Profile View" in the user's activity history.
        /// </remarks>
        /// <returns>Current user's profile information</returns>
        /// <response code="200">User profile retrieved successfully</response>
        /// <response code="401">Unauthorized - invalid or expired token</response>
        /// <response code="404">User not found</response>
        /// <response code="500">Internal server error</response>
        [HttpGet("user")]
        [Authorize]
        [SwaggerOperation(
            Summary = "Get current authenticated user's profile information",
            Description = "Retrieves complete profile data for the authenticated user",
            OperationId = "GetCurrentUser",
            Tags = new[] { "User Management" }
        )]
        [SwaggerResponse(200, "User profile retrieved successfully", typeof(CurrentUserResponse))]
        [SwaggerResponse(401, "Unauthorized", typeof(ErrorResponse))]
        [SwaggerResponse(404, "User not found", typeof(ErrorResponse))]
        [SwaggerResponse(500, "Internal server error", typeof(ErrorResponse))]
        public async Task<IActionResult> GetCurrentUser()
        {
            var response = await _userService.GetCurrentUserAsync();
            await _activityLoggingService.LogActivityAsync(
                response.Id,
                "Profile View",
                "User viewed their profile");
            return Ok(response);
        }

        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetById(Guid id)
        {
            var response = await _userService.GetByIdAsync(id);
            var currentUserId = _currentUserService.GetUserId();
            await _activityLoggingService.LogActivityAsync(
                currentUserId,
                "User Lookup",
                $"Viewed user profile: {id}");
            return Ok(response);
        }

        [HttpDelete("user/{id}")]
        [Authorize]
        public async Task<IActionResult> Delete(Guid id)
        {
            var currentUserId = _currentUserService.GetUserId();
            await _userService.DeleteAsync(id);
            await _activityLoggingService.LogActivityAsync(
                currentUserId,
                "Account Deletion",
                $"Deleted user account: {id}");
            return Ok();
        }

        /// <summary>
        /// Logout user and invalidate access token
        /// </summary>
        /// <remarks>
        /// Logs out the current user by adding their JWT token to the blacklist, preventing further use.
        ///
        /// **Logout Process:**
        /// 1. Extracts the JWT token from the Authorization header
        /// 2. Adds the token to the blacklist with its expiry time
        /// 3. Logs the logout activity
        /// 4. Returns success confirmation
        ///
        /// **Token Blacklisting:**
        /// Once blacklisted, the token cannot be used for any authenticated requests until it naturally expires.
        ///
        /// **Security Note:**
        /// Always call this endpoint when users log out to ensure their tokens are immediately invalidated.
        /// </remarks>
        /// <returns>Logout confirmation message</returns>
        /// <response code="200">Logout successful - token invalidated</response>
        /// <response code="400">No token provided or invalid token format</response>
        /// <response code="401">Unauthorized - invalid or expired token</response>
        /// <response code="500">Internal server error during logout</response>
        [HttpPost("logout")]
        [Authorize]
        [SwaggerOperation(
            Summary = "Logout user and invalidate access token",
            Description = "Invalidates the current user's JWT token by adding it to the blacklist",
            OperationId = "LogoutUser",
            Tags = new[] { "Authentication" }
        )]
        [SwaggerResponse(200, "Logout successful", typeof(object))]
        [SwaggerResponse(400, "No token provided", typeof(ErrorResponse))]
        [SwaggerResponse(401, "Unauthorized", typeof(ErrorResponse))]
        [SwaggerResponse(500, "Internal server error", typeof(ErrorResponse))]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
                var userId = _currentUserService.GetUserId();

                if (!string.IsNullOrEmpty(token))
                {
                    await _tokenService.RevokeTokenAsync(token);
                    await _activityLoggingService.LogActivityAsync(
                        userId,
                        "Logout",
                        "User logged out successfully");
                    return Ok(new { Message = "Logged out successfully" });
                }
                return BadRequest(new { Message = "No token provided" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return BadRequest(new { Message = "Error processing logout" });
            }
        }

        [HttpGet("login-history")]
        [Authorize]
        public async Task<ActionResult<LoginHistoryResponse>> GetLoginHistory()
        {
            try
            {
                var response = await _userService.GetLoginHistoryAsync();
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving login history");
                return BadRequest(new ErrorResponse { Message = ex.Message });
            }
        }

        [HttpGet("account-activity")]
        [Authorize]
        public async Task<ActionResult<AccountActivityResponse>> GetAccountActivity()
        {
            try
            {
                var response = await _userService.GetAccountActivitiesAsync();
                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving account activities");
                return BadRequest(new ErrorResponse { Message = ex.Message });
            }
        }
    }
}
