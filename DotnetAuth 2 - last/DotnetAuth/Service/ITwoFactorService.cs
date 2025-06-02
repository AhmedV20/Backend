using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;

namespace DotnetAuth.Service
{
    public interface ITwoFactorService
    {
        // Setup and management
        Task<Setup2faResponse> Setup2faAsync(string userId, Setup2faRequest request);
        Task<Verify2faSetupResponse> Verify2faSetupAsync(string userId, Verify2faSetupRequest request);
        Task<Disable2faResponse> Disable2faAsync(string userId, Disable2faRequest request);
        
        // Authentication
        Task<bool> ValidateTwoFactorCodeAsync(ApplicationUser user, string code);
        Task<TwoFactorLoginResponse> VerifyTwoFactorLoginAsync(TwoFactorLoginRequest request);
        
        // Recovery
        Task<List<string>> GenerateRecoveryCodesAsync(string userId, int count = 10);
        Task<bool> ValidateRecoveryCodeAsync(string userId, string recoveryCode);
        
        // Helpers
        Task<bool> Is2faEnabledAsync(string userId);
        Task<string> GetTwoFactorTypeAsync(string userId);
        Task<string> GenerateTwoFactorCodeAsync(string userId);
    }
}
