using DotnetAuth.Domain.Contracts;

namespace DotnetAuth.Service
{
    public interface IExternalAuthService
    {
        Task<ExternalAuthResponse> AuthenticateGoogleAsync(string idToken);
        Task<ExternalAuthResponse> RegisterExternalUserAsync(ExternalUserRegistrationRequest request);
    }
}
