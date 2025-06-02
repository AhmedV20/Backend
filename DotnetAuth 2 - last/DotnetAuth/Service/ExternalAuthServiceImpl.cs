using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using DotnetAuth.Infrastructure.Context;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace DotnetAuth.Service
{
    public class ExternalAuthServiceImpl : IExternalAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenService _tokenService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ExternalAuthServiceImpl> _logger;
        private readonly IEmailService _emailService;
        private readonly ApplicationDbContext _dbContext;
        private readonly IActivityLoggingService _activityLoggingService;

        public ExternalAuthServiceImpl(
            UserManager<ApplicationUser> userManager,
            ITokenService tokenService,
            IConfiguration configuration,
            ILogger<ExternalAuthServiceImpl> logger,
            IEmailService emailService,
            ApplicationDbContext dbContext,
            IActivityLoggingService activityLoggingService)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _configuration = configuration;
            _logger = logger;
            _emailService = emailService;
            _dbContext = dbContext;
            _activityLoggingService = activityLoggingService;
        }

        public async Task<ExternalAuthResponse> AuthenticateGoogleAsync(string idToken)
        {
            try
            {
                _logger.LogInformation("Authenticating with Google, token length: {Length}", idToken?.Length ?? 0);

                // For development/testing, we can skip validation if the client ID is not set
                GoogleJsonWebSignature.Payload payload;

                try
                {
                    // First, try to validate as an ID token
                    var validationSettings = new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[] { _configuration["Authentication:Google:ClientId"] }
                    };

                    try
                    {
                        // Try to validate as an ID token
                        payload = await GoogleJsonWebSignature.ValidateAsync(idToken, validationSettings);
                        _logger.LogInformation("Google ID token validated successfully for email: {Email}", payload.Email);
                    }
                    catch (InvalidJwtException)
                    {
                        // If ID token validation fails, try to get user info using the token as an access token
                        _logger.LogInformation("ID token validation failed, trying as access token");

                        // Create an HttpClient to call Google's userinfo endpoint
                        using var httpClient = new HttpClient();
                        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {idToken}");

                        var response = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v3/userinfo");
                        if (!response.IsSuccessStatusCode)
                        {
                            // Create a custom exception instead of InvalidJwtException with 2 parameters
                            throw new Exception("Invalid Google token");
                        }

                        var userInfoJson = await response.Content.ReadAsStringAsync();
                        _logger.LogInformation("Google user info: {UserInfo}", userInfoJson);

                        // Parse the JSON response
                        var userInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoJson);

                        // Create a payload from the user info
                        payload = new GoogleJsonWebSignature.Payload
                        {
                            Email = userInfo.ContainsKey("email") ? userInfo["email"].ToString() : "",
                            EmailVerified = userInfo.ContainsKey("email_verified") && bool.Parse(userInfo["email_verified"].ToString()),
                            Name = userInfo.ContainsKey("name") ? userInfo["name"].ToString() : "",
                            GivenName = userInfo.ContainsKey("given_name") ? userInfo["given_name"].ToString() : "",
                            FamilyName = userInfo.ContainsKey("family_name") ? userInfo["family_name"].ToString() : "",
                            Subject = userInfo.ContainsKey("sub") ? userInfo["sub"].ToString() : ""
                        };

                        _logger.LogInformation("Google access token validated successfully for email: {Email}", payload.Email);
                    }
                }
                catch (Exception ex) when (_configuration["Authentication:Google:ClientId"] == "YOUR_GOOGLE_CLIENT_ID" ||
                                          string.IsNullOrEmpty(_configuration["Authentication:Google:ClientId"]))
                {
                    // In development mode with placeholder client ID, create a mock payload
                    _logger.LogWarning("Using mock Google payload due to missing client ID configuration: {Error}", ex.Message);
                    payload = new GoogleJsonWebSignature.Payload
                    {
                        Email = "test@example.com",
                        EmailVerified = true,
                        Name = "Test User",
                        GivenName = "Test",
                        FamilyName = "User",
                        Subject = "mock-google-id-123"
                    };
                }

                // Check if user exists
                var user = await _userManager.FindByEmailAsync(payload.Email);

                if (user == null)
                {
                    _logger.LogInformation("User with email {Email} not found, registration required", payload.Email);
                    // User doesn't exist, return response indicating registration is required
                    return new ExternalAuthResponse
                    {
                        Success = true,
                        Message = "User not found. Registration required.",
                        Email = payload.Email,
                        FirstName = payload.GivenName,
                        LastName = payload.FamilyName,
                        RequiresRegistration = true
                    };
                }

                // Check if the user has external login with Google
                if (string.IsNullOrEmpty(user.ExternalProvider) || user.ExternalProvider != "Google")
                {
                    // User exists but doesn't have Google as external provider
                    return new ExternalAuthResponse
                    {
                        Success = false,
                        Message = "An account with this email already exists. Please log in with your password."
                    };
                }

                // Check if two-factor authentication is enabled
                if (user.TwoFactorEnabled)
                {
                    // Generate and send two-factor code
                    return new ExternalAuthResponse
                    {
                        Success = true,
                        Message = "Two-factor authentication required",
                        Email = user.Email,
                        UserId = user.Id,
                        RequiresTwoFactor = true
                    };
                }

                // Generate tokens
                var accessToken = await _tokenService.GenerateToken(user);
                var refreshToken = _tokenService.GenerateRefreshToken();

                // Hash and store refresh token
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
                user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(30);

                // Update user
                await _userManager.UpdateAsync(user);

                // Log login activity
                await LogLoginActivity(user);

                return new ExternalAuthResponse
                {
                    Success = true,
                    Message = "Authentication successful",
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserId = user.Id
                };
            }
            catch (InvalidJwtException ex)
            {
                _logger.LogError(ex, "Invalid Google ID token");
                return new ExternalAuthResponse
                {
                    Success = false,
                    Message = "Invalid Google token"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error authenticating with Google");
                return new ExternalAuthResponse
                {
                    Success = false,
                    Message = "An error occurred during authentication"
                };
            }
        }

        public async Task<ExternalAuthResponse> RegisterExternalUserAsync(ExternalUserRegistrationRequest request)
        {
            try
            {
                _logger.LogInformation("Registering external user with provider: {Provider}", request.Provider);

                if (!request.IsValidRegistrationRole())
                {
                    _logger.LogWarning("Invalid role for registration: {Role}", request.Role);
                    return new ExternalAuthResponse
                    {
                        Success = false,
                        Message = "Invalid role for registration"
                    };
                }

                // For development/testing, we can skip validation if the client ID is not set
                GoogleJsonWebSignature.Payload payload;

                try
                {
                    // First, try to validate as an ID token
                    var validationSettings = new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[] { _configuration["Authentication:Google:ClientId"] }
                    };

                    try
                    {
                        // Try to validate as an ID token
                        payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, validationSettings);
                        _logger.LogInformation("Google ID token validated successfully for registration, email: {Email}", payload.Email);
                    }
                    catch (InvalidJwtException)
                    {
                        // If ID token validation fails, try to get user info using the token as an access token
                        _logger.LogInformation("ID token validation failed for registration, trying as access token");

                        // Create an HttpClient to call Google's userinfo endpoint
                        using var httpClient = new HttpClient();
                        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {request.IdToken}");

                        var response = await httpClient.GetAsync("https://www.googleapis.com/oauth2/v3/userinfo");
                        if (!response.IsSuccessStatusCode)
                        {
                            // Create a custom exception instead of InvalidJwtException with 2 parameters
                            throw new Exception("Invalid Google token for registration");
                        }

                        var userInfoJson = await response.Content.ReadAsStringAsync();
                        _logger.LogInformation("Google user info for registration: {UserInfo}", userInfoJson);

                        // Parse the JSON response
                        var userInfo = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(userInfoJson);

                        // Create a payload from the user info
                        payload = new GoogleJsonWebSignature.Payload
                        {
                            Email = userInfo.ContainsKey("email") ? userInfo["email"].ToString() : "",
                            EmailVerified = userInfo.ContainsKey("email_verified") && bool.Parse(userInfo["email_verified"].ToString()),
                            Name = userInfo.ContainsKey("name") ? userInfo["name"].ToString() : "",
                            GivenName = userInfo.ContainsKey("given_name") ? userInfo["given_name"].ToString() : "",
                            FamilyName = userInfo.ContainsKey("family_name") ? userInfo["family_name"].ToString() : "",
                            Subject = userInfo.ContainsKey("sub") ? userInfo["sub"].ToString() : ""
                        };

                        _logger.LogInformation("Google access token validated successfully for registration, email: {Email}", payload.Email);
                    }
                }
                catch (Exception ex) when (_configuration["Authentication:Google:ClientId"] == "YOUR_GOOGLE_CLIENT_ID" ||
                                          string.IsNullOrEmpty(_configuration["Authentication:Google:ClientId"]))
                {
                    // In development mode with placeholder client ID, create a mock payload
                    _logger.LogWarning("Using mock Google payload for registration due to missing client ID configuration: {Error}", ex.Message);
                    payload = new GoogleJsonWebSignature.Payload
                    {
                        Email = "test@example.com",
                        EmailVerified = true,
                        Name = "Test User",
                        GivenName = "Test",
                        FamilyName = "User",
                        Subject = "mock-google-id-" + Guid.NewGuid().ToString("N").Substring(0, 8)
                    };
                }

                // Check if user already exists
                var existingUser = await _userManager.FindByEmailAsync(payload.Email);
                if (existingUser != null)
                {
                    return new ExternalAuthResponse
                    {
                        Success = false,
                        Message = "User with this email already exists"
                    };
                }

                // Create new user
                var user = new ApplicationUser
                {
                    Email = payload.Email,
                    UserName = payload.Email,
                    FirstName = payload.GivenName ?? "User",
                    LastName = payload.FamilyName ?? "",
                    Gender = request.Gender,
                    Role = request.Role.ToString(),
                    EmailConfirmed = true, // Email is verified by Google
                    IsEmailConfirmed = true,
                    ExternalProvider = "Google",
                    ExternalProviderId = payload.Subject, // Google's user ID
                    CreateAt = DateTime.UtcNow,
                    UpdateAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to create user: {errors}", errors);
                    return new ExternalAuthResponse
                    {
                        Success = false,
                        Message = $"Failed to create user: {errors}"
                    };
                }

                // Add user to role
                await _userManager.AddToRoleAsync(user, request.Role.ToString());

                // For simplicity, we'll just log that a default profile picture would be assigned
                // In a real implementation, you would inject IProfilePictureService and use it directly
                _logger.LogInformation("Default profile picture would be assigned to user {UserId}", user.Id);

                // Generate tokens
                var accessToken = await _tokenService.GenerateToken(user);
                var refreshToken = _tokenService.GenerateRefreshToken();

                // Hash and store refresh token
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
                user.RefreshToken = Convert.ToBase64String(refreshTokenHash);
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(30);

                // Update user
                await _userManager.UpdateAsync(user);

                // Log registration activity
                await _activityLoggingService.LogActivityAsync(
                    user.Id,
                    "Registration",
                    "User registered with Google authentication");

                // Log login activity
                await LogLoginActivity(user);

                return new ExternalAuthResponse
                {
                    Success = true,
                    Message = "Registration successful",
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    UserId = user.Id
                };
            }
            catch (InvalidJwtException ex)
            {
                _logger.LogError(ex, "Invalid Google ID token");
                return new ExternalAuthResponse
                {
                    Success = false,
                    Message = "Invalid Google token"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registering user with Google");
                return new ExternalAuthResponse
                {
                    Success = false,
                    Message = "An error occurred during registration"
                };
            }
        }

        private async Task LogLoginActivity(ApplicationUser user)
        {
            try
            {
                var loginHistory = new LoginHistory
                {
                    UserId = user.Id,
                    LoginTime = DateTime.UtcNow,
                    IpAddress = "External Auth", // In a real app, get the actual IP
                    Device = "Google Authentication",
                    Location = "Unknown"
                };

                _dbContext.LoginHistory.Add(loginHistory);
                await _dbContext.SaveChangesAsync();

                await _activityLoggingService.LogActivityAsync(
                    user.Id,
                    "Login",
                    "User logged in with Google authentication");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging login activity for user {UserId}", user.Id);
                // Don't throw - this is a non-critical operation
            }
        }
    }
}
