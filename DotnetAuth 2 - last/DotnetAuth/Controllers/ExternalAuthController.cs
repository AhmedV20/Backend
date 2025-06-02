using DotnetAuth.Domain.Contracts;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers
{
    [Route("api/external-auth")]
    [ApiController]
    public class ExternalAuthController : ControllerBase
    {
        private readonly IExternalAuthService _externalAuthService;
        private readonly ILogger<ExternalAuthController> _logger;
        private readonly IActivityLoggingService _activityLoggingService;

        public ExternalAuthController(
            IExternalAuthService externalAuthService,
            ILogger<ExternalAuthController> logger,
            IActivityLoggingService activityLoggingService)
        {
            _externalAuthService = externalAuthService;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
        }

        [HttpPost("google")]
        [AllowAnonymous]
        public async Task<ActionResult<ExternalAuthResponse>> GoogleLogin([FromBody] GoogleAuthRequest request)
        {
            try
            {
                _logger.LogInformation("Received Google authentication request");

                var response = await _externalAuthService.AuthenticateGoogleAsync(request.IdToken);

                _logger.LogInformation("Google authentication response: {Success}, RequiresRegistration: {RequiresRegistration}",
                    response.Success, response.RequiresRegistration);

                if (response.Success && !string.IsNullOrEmpty(response.UserId))
                {
                    await _activityLoggingService.LogActivityAsync(
                        response.UserId,
                        "Google Authentication",
                        "User authenticated with Google");
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Google authentication");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("google/register")]
        [AllowAnonymous]
        public async Task<ActionResult<ExternalAuthResponse>> GoogleRegister([FromBody] ExternalUserRegistrationRequest request)
        {
            try
            {
                _logger.LogInformation("Received Google registration request for provider: {Provider}", request.Provider);

                if (request.Provider != "Google")
                {
                    return BadRequest(new { Message = "Invalid provider" });
                }

                if (!request.IsValidRegistrationRole())
                {
                    _logger.LogWarning("Invalid role for registration: {Role}", request.Role);
                    return BadRequest(new { Message = "Invalid role for registration. Only Doctor or Patient roles are allowed." });
                }

                var response = await _externalAuthService.RegisterExternalUserAsync(request);

                _logger.LogInformation("Google registration response: {Success}", response.Success);

                if (response.Success && !string.IsNullOrEmpty(response.UserId))
                {
                    await _activityLoggingService.LogActivityAsync(
                        response.UserId,
                        "Google Registration",
                        "User registered with Google");
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Google registration");
                return BadRequest(new { Message = ex.Message });
            }
        }
    }
}
