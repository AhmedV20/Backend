using System.ComponentModel.DataAnnotations;

namespace DotnetAuth.Domain.Contracts
{
    public class ExternalAuthRequest
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        public string IdToken { get; set; }
    }

    public class GoogleAuthRequest
    {
        [Required]
        public string IdToken { get; set; }
    }

    public class ExternalAuthResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserId { get; set; }
        public bool RequiresRegistration { get; set; }
        public bool RequiresTwoFactor { get; set; }
    }

    public class ExternalUserRegistrationRequest
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        public string IdToken { get; set; }

        [Required]
        public Gender Gender { get; set; }

        [Required]
        public UserRole Role { get; set; }

        public bool IsValidRegistrationRole()
        {
            return Role == UserRole.Doctor || Role == UserRole.Patient;
        }
    }
}
