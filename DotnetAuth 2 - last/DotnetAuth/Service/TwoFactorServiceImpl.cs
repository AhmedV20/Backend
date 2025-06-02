using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OtpNet;

namespace DotnetAuth.Service
{
    public class TwoFactorServiceImpl : ITwoFactorService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly ILogger<TwoFactorServiceImpl> _logger;

        public TwoFactorServiceImpl(
            UserManager<ApplicationUser> userManager,
            ITokenService tokenService,
            IEmailService emailService,
            ILogger<TwoFactorServiceImpl> logger)
        {
            _userManager = userManager;
            _tokenService = tokenService;
            _emailService = emailService;
            _logger = logger;
        }

        public async Task<Setup2faResponse> Setup2faAsync(string userId, Setup2faRequest request)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return new Setup2faResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                // Generate a secret key for 2FA
                string secret = GenerateSecretKey();
                string verificationCode = string.Empty;
                string qrCodeUrl = string.Empty;

                switch (request.TwoFactorType.ToLower())
                {
                    case "email":
                        // For email-based 2FA, we'll send a verification code
                        verificationCode = GenerateSecureOtp();

                        // Send verification email
                        var subject = "Two-Factor Authentication Setup";
                        var body = $@"
                            <h2>Two-Factor Authentication Setup</h2>
                            <p>You are setting up two-factor authentication for your account.</p>
                            <p>Your verification code is: <strong>{verificationCode}</strong></p>
                            <p>This code will expire in 15 minutes.</p>
                            <p>If you didn't request this setup, please secure your account immediately.</p>";

                        await _emailService.SendEmailAsync(user.Email, subject, body);
                        break;

                    case "sms":
                        // For SMS-based 2FA, we would send a verification code via SMS
                        // This is a placeholder - you would integrate with an SMS service
                        verificationCode = GenerateSecureOtp();

                        // In a real implementation, you would send an SMS here
                        _logger.LogInformation("SMS verification code for user {UserId}: {Code}", userId, verificationCode);
                        break;

                    case "authenticator":
                        // For authenticator app-based 2FA, we generate a QR code URL
                        // Format: otpauth://totp/Issuer:AccountName?secret=SECRET&issuer=Issuer&algorithm=SHA1&digits=6&period=30
                        var accountName = Uri.EscapeDataString(user.Email ?? "user");
                        var issuer = Uri.EscapeDataString("DotnetAuth");
                        qrCodeUrl = $"otpauth://totp/{issuer}:{accountName}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
                        break;

                    default:
                        return new Setup2faResponse
                        {
                            Success = false,
                            Message = "Invalid two-factor authentication type"
                        };
                }

                // Store the 2FA setup information temporarily
                user.TwoFactorSecret = secret;
                user.TwoFactorType = request.TwoFactorType;
                user.Otp = verificationCode;
                user.OtpExpiryTime = DateTime.UtcNow.AddMinutes(15);

                await _userManager.UpdateAsync(user);

                return new Setup2faResponse
                {
                    Success = true,
                    Message = $"{request.TwoFactorType} two-factor authentication setup initiated",
                    Secret = secret,
                    QrCodeUrl = qrCodeUrl,
                    VerificationCode = verificationCode // Only for development/testing
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up 2FA for user {UserId}", userId);
                return new Setup2faResponse
                {
                    Success = false,
                    Message = "An error occurred while setting up two-factor authentication"
                };
            }
        }

        public async Task<Verify2faSetupResponse> Verify2faSetupAsync(string userId, Verify2faSetupRequest request)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return new Verify2faSetupResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                bool isValid = false;

                // Verify based on the 2FA type
                switch (user.TwoFactorType?.ToLower())
                {
                    case "email":
                    case "sms":
                        // For email and SMS, verify the OTP
                        if (user.Otp == request.VerificationCode && user.OtpExpiryTime > DateTime.UtcNow)
                        {
                            isValid = true;
                        }
                        break;

                    case "authenticator":
                        // For authenticator apps, validate the TOTP code
                        isValid = ValidateAuthenticatorCode(user.TwoFactorSecret, request.VerificationCode);
                        break;

                    default:
                        return new Verify2faSetupResponse
                        {
                            Success = false,
                            Message = "Invalid two-factor authentication type"
                        };
                }

                if (!isValid)
                {
                    return new Verify2faSetupResponse
                    {
                        Success = false,
                        Message = "Invalid verification code"
                    };
                }

                // Generate recovery codes
                var recoveryCodes = await GenerateRecoveryCodesAsync(userId);

                // Enable 2FA for the user
                user.TwoFactorEnabled = true;
                user.TwoFactorSetupDate = DateTime.UtcNow;
                user.Otp = null;
                user.OtpExpiryTime = null;

                // Store recovery codes (in a real app, these should be hashed)
                user.TwoFactorRecoveryCodes = JsonSerializer.Serialize(recoveryCodes);

                await _userManager.UpdateAsync(user);

                return new Verify2faSetupResponse
                {
                    Success = true,
                    Message = "Two-factor authentication has been enabled",
                    RecoveryCodes = recoveryCodes
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying 2FA setup for user {UserId}", userId);
                return new Verify2faSetupResponse
                {
                    Success = false,
                    Message = "An error occurred while verifying two-factor authentication setup"
                };
            }
        }

        public async Task<Disable2faResponse> Disable2faAsync(string userId, Disable2faRequest request)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return new Disable2faResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                // Verify password
                var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
                if (!isPasswordValid)
                {
                    return new Disable2faResponse
                    {
                        Success = false,
                        Message = "Invalid password"
                    };
                }

                // Disable 2FA
                user.TwoFactorEnabled = false;
                user.TwoFactorSecret = null;
                user.TwoFactorType = null;
                user.TwoFactorRecoveryCodes = null;
                user.TwoFactorSetupDate = null;

                await _userManager.UpdateAsync(user);

                return new Disable2faResponse
                {
                    Success = true,
                    Message = "Two-factor authentication has been disabled"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling 2FA for user {UserId}", userId);
                return new Disable2faResponse
                {
                    Success = false,
                    Message = "An error occurred while disabling two-factor authentication"
                };
            }
        }

        public async Task<bool> ValidateTwoFactorCodeAsync(ApplicationUser user, string code)
        {
            if (user == null || !user.TwoFactorEnabled || string.IsNullOrEmpty(code))
            {
                return false;
            }

            switch (user.TwoFactorType?.ToLower())
            {
                case "email":
                case "sms":
                    // For email and SMS, verify the OTP
                    return user.Otp == code && user.OtpExpiryTime > DateTime.UtcNow;

                case "authenticator":
                    // For authenticator apps, validate the TOTP code
                    return ValidateAuthenticatorCode(user.TwoFactorSecret, code);

                default:
                    return false;
            }
        }

        public async Task<TwoFactorLoginResponse> VerifyTwoFactorLoginAsync(TwoFactorLoginRequest request)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(request.Email);
                if (user == null)
                {
                    return new TwoFactorLoginResponse
                    {
                        Success = false,
                        Message = "User not found"
                    };
                }

                if (!user.TwoFactorEnabled)
                {
                    return new TwoFactorLoginResponse
                    {
                        Success = false,
                        Message = "Two-factor authentication is not enabled for this user"
                    };
                }

                bool isValid = await ValidateTwoFactorCodeAsync(user, request.TwoFactorCode);
                if (!isValid)
                {
                    // Check if it's a recovery code
                    isValid = await ValidateRecoveryCodeAsync(user.Id, request.TwoFactorCode);
                    if (!isValid)
                    {
                        return new TwoFactorLoginResponse
                        {
                            Success = false,
                            Message = "Invalid verification code"
                        };
                    }
                }

                // Generate access token
                var accessToken = await _tokenService.GenerateToken(user);

                // Generate refresh token
                var refreshToken = _tokenService.GenerateRefreshToken();

                // Hash the refresh token and store it in the database
                using var sha256 = SHA256.Create();
                var refreshTokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
                user.RefreshToken = Convert.ToBase64String(refreshTokenHash);

                // Set refresh token expiry (30 days for "Remember Device")
                user.RefreshTokenExpiryTime = request.RememberDevice
                    ? DateTime.Now.AddDays(30)
                    : DateTime.Now.AddDays(1);

                // Clear the OTP if it was used
                if (user.TwoFactorType?.ToLower() == "email" || user.TwoFactorType?.ToLower() == "sms")
                {
                    user.Otp = null;
                    user.OtpExpiryTime = null;
                }

                await _userManager.UpdateAsync(user);

                return new TwoFactorLoginResponse
                {
                    Success = true,
                    Message = "Two-factor authentication successful",
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying 2FA login for email: {Email}", request.Email);
                return new TwoFactorLoginResponse
                {
                    Success = false,
                    Message = "An error occurred during two-factor authentication"
                };
            }
        }

        public async Task<List<string>> GenerateRecoveryCodesAsync(string userId, int count = 10)
        {
            // Generate new recovery codes
            var recoveryCodes = new List<string>();
            for (int i = 0; i < count; i++)
            {
                recoveryCodes.Add(GenerateRecoveryCode());
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                // Log that old codes are being invalidated
                if (!string.IsNullOrEmpty(user.TwoFactorRecoveryCodes))
                {
                    _logger.LogInformation("Invalidating old recovery codes for user {UserId}", userId);
                }

                // Store the new recovery codes, overwriting any existing ones
                user.TwoFactorRecoveryCodes = JsonSerializer.Serialize(recoveryCodes);
                await _userManager.UpdateAsync(user);

                _logger.LogInformation("Generated {Count} new recovery codes for user {UserId}", count, userId);
            }
            else
            {
                _logger.LogWarning("Attempted to generate recovery codes for non-existent user {UserId}", userId);
            }

            return recoveryCodes;
        }

        public async Task<bool> ValidateRecoveryCodeAsync(string userId, string recoveryCode)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("Recovery code validation failed: User {UserId} not found", userId);
                return false;
            }

            if (string.IsNullOrEmpty(user.TwoFactorRecoveryCodes))
            {
                _logger.LogWarning("Recovery code validation failed: No recovery codes found for user {UserId}", userId);
                return false;
            }

            try
            {
                var recoveryCodes = JsonSerializer.Deserialize<List<string>>(user.TwoFactorRecoveryCodes);

                if (recoveryCodes.Contains(recoveryCode))
                {
                    _logger.LogInformation("Valid recovery code used for user {UserId}", userId);

                    // Remove the used recovery code
                    recoveryCodes.Remove(recoveryCode);
                    user.TwoFactorRecoveryCodes = JsonSerializer.Serialize(recoveryCodes);
                    await _userManager.UpdateAsync(user);

                    _logger.LogInformation("Recovery code removed after use for user {UserId}. {Count} codes remaining.",
                        userId, recoveryCodes.Count);

                    return true;
                }
                else
                {
                    _logger.LogWarning("Invalid recovery code attempted for user {UserId}", userId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating recovery code for user {UserId}", userId);
            }

            return false;
        }

        public async Task<bool> Is2faEnabledAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user != null && user.TwoFactorEnabled;
        }

        public async Task<string> GetTwoFactorTypeAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user?.TwoFactorType;
        }

        public async Task<string> GenerateTwoFactorCodeAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || !user.TwoFactorEnabled)
            {
                return null;
            }

            switch (user.TwoFactorType?.ToLower())
            {
                case "email":
                case "sms":
                    var code = GenerateSecureOtp();
                    user.Otp = code;
                    user.OtpExpiryTime = DateTime.UtcNow.AddMinutes(15);
                    await _userManager.UpdateAsync(user);

                    if (user.TwoFactorType?.ToLower() == "email")
                    {
                        // Send verification email
                        var subject = "Two-Factor Authentication Code";
                        var body = $@"
                            <h2>Two-Factor Authentication</h2>
                            <p>Your verification code is: <strong>{code}</strong></p>
                            <p>This code will expire in 15 minutes.</p>
                            <p>If you didn't request this code, please secure your account immediately.</p>";

                        await _emailService.SendEmailAsync(user.Email, subject, body);
                    }
                    else
                    {
                        // In a real implementation, you would send an SMS here
                        _logger.LogInformation("SMS verification code for user {UserId}: {Code}", userId, code);
                    }

                    return code;

                case "authenticator":
                    // For authenticator apps, we don't need to generate a code
                    return null;

                default:
                    return null;
            }
        }

        #region Helper Methods

        private string GenerateSecretKey()
        {
            var key = new byte[20]; // 160 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return Base32Encode(key);
        }

        private string Base32Encode(byte[] data)
        {
            const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var result = new StringBuilder();

            for (int i = 0; i < data.Length; i += 5)
            {
                var chunk = new byte[5];
                var chunkLength = Math.Min(5, data.Length - i);
                Array.Copy(data, i, chunk, 0, chunkLength);

                // Convert 5 bytes (40 bits) to 8 base32 characters
                ulong value = 0;
                for (int j = 0; j < chunkLength; j++)
                {
                    value = (value << 8) | chunk[j];
                }

                // Pad with zeros if needed
                value <<= (5 - chunkLength) * 8;

                // Extract 5-bit groups and convert to base32
                var chars = new char[8];
                for (int j = 7; j >= 0; j--)
                {
                    chars[j] = base32Chars[(int)(value & 0x1F)];
                    value >>= 5;
                }

                // Add only the needed characters (no padding for our use case)
                var neededChars = (chunkLength * 8 + 4) / 5;
                result.Append(chars, 8 - neededChars, neededChars);
            }

            return result.ToString();
        }

        private byte[] Base32Decode(string base32)
        {
            const string base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var result = new List<byte>();

            // Remove any whitespace and convert to uppercase
            base32 = base32.Replace(" ", "").Replace("-", "").ToUpper();

            for (int i = 0; i < base32.Length; i += 8)
            {
                var chunk = base32.Substring(i, Math.Min(8, base32.Length - i));
                ulong value = 0;

                foreach (char c in chunk)
                {
                    var index = base32Chars.IndexOf(c);
                    if (index < 0) throw new ArgumentException($"Invalid Base32 character: {c}");
                    value = (value << 5) | (uint)index;
                }

                // Extract bytes from the accumulated value
                var byteCount = (chunk.Length * 5) / 8;
                for (int j = byteCount - 1; j >= 0; j--)
                {
                    result.Add((byte)((value >> (j * 8)) & 0xFF));
                }
            }

            return result.ToArray();
        }

        private string GenerateSecureOtp()
        {
            using var rng = RandomNumberGenerator.Create();
            var randomNumber = new byte[4];
            rng.GetBytes(randomNumber);
            var otpValue = BitConverter.ToUInt32(randomNumber, 0) % 1000000;
            return otpValue.ToString("D6");
        }

        private string GenerateRecoveryCode()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            var code = new StringBuilder();

            for (int i = 0; i < 10; i++)
            {
                code.Append(chars[random.Next(chars.Length)]);
                if (i == 4) code.Append('-');
            }

            return code.ToString();
        }

        private bool ValidateAuthenticatorCode(string secret, string code)
        {
            try
            {
                // Validate input parameters
                if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(code))
                {
                    _logger.LogWarning("ValidateAuthenticatorCode: Secret or code is null/empty");
                    return false;
                }

                // Ensure code is exactly 6 digits
                if (code.Length != 6 || !code.All(char.IsDigit))
                {
                    _logger.LogWarning("ValidateAuthenticatorCode: Code is not 6 digits");
                    return false;
                }

                // Convert the Base32 secret to bytes
                byte[] secretBytes;
                try
                {
                    secretBytes = Base32Decode(secret);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "ValidateAuthenticatorCode: Invalid Base32 secret format");
                    return false;
                }

                // Create TOTP instance with the secret
                var totp = new Totp(secretBytes);

                // Validate the code with a time window tolerance (usually 1 step = 30 seconds)
                // This allows for slight time differences between server and client
                var isValid = totp.VerifyTotp(code, out long timeStepMatched, window: VerificationWindow.RfcSpecifiedNetworkDelay);

                if (isValid)
                {
                    _logger.LogInformation("ValidateAuthenticatorCode: Valid TOTP code provided");
                }
                else
                {
                    _logger.LogWarning("ValidateAuthenticatorCode: Invalid TOTP code provided");
                }

                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ValidateAuthenticatorCode: Error validating TOTP code");
                return false;
            }
        }

        #endregion
    }
}
