using DotnetAuth.Domain.Contracts;
using DotnetAuth.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAuth.Controllers
{
    [Route("api/2fa")]
    [ApiController]
    public class TwoFactorController : ControllerBase
    {
        private readonly ITwoFactorService _twoFactorService;
        private readonly ICurrentUserService _currentUserService;
        private readonly ILogger<TwoFactorController> _logger;
        private readonly IActivityLoggingService _activityLoggingService;

        public TwoFactorController(
            ITwoFactorService twoFactorService,
            ICurrentUserService currentUserService,
            ILogger<TwoFactorController> logger,
            IActivityLoggingService activityLoggingService)
        {
            _twoFactorService = twoFactorService;
            _currentUserService = currentUserService;
            _logger = logger;
            _activityLoggingService = activityLoggingService;
        }

        [HttpPost("setup")]
        [Authorize]
        public async Task<ActionResult<Setup2faResponse>> Setup2fa([FromBody] Setup2faRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var response = await _twoFactorService.Setup2faAsync(userId, request);

                if (response.Success)
                {
                    await _activityLoggingService.LogActivityAsync(
                        userId,
                        "2FA Setup",
                        $"Two-factor authentication setup initiated using {request.TwoFactorType}");
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting up 2FA");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("verify-setup")]
        [Authorize]
        public async Task<ActionResult<Verify2faSetupResponse>> VerifySetup([FromBody] Verify2faSetupRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var response = await _twoFactorService.Verify2faSetupAsync(userId, request);

                if (response.Success)
                {
                    await _activityLoggingService.LogActivityAsync(
                        userId,
                        "2FA Enabled",
                        "Two-factor authentication successfully enabled");
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying 2FA setup");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("disable")]
        [Authorize]
        public async Task<ActionResult<Disable2faResponse>> Disable2fa([FromBody] Disable2faRequest request)
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var response = await _twoFactorService.Disable2faAsync(userId, request);

                if (response.Success)
                {
                    await _activityLoggingService.LogActivityAsync(
                        userId,
                        "2FA Disabled",
                        "Two-factor authentication disabled");
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error disabling 2FA");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("verify")]
        [AllowAnonymous]
        public async Task<ActionResult<TwoFactorLoginResponse>> VerifyTwoFactorLogin([FromBody] TwoFactorLoginRequest request)
        {
            try
            {
                var response = await _twoFactorService.VerifyTwoFactorLoginAsync(request);

                if (response.Success)
                {
                    // We don't have the user ID here, but we can log it after successful verification
                    // This would be handled in the service
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying 2FA login");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpGet("status")]
        [Authorize]
        public async Task<ActionResult> Get2faStatus()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var isEnabled = await _twoFactorService.Is2faEnabledAsync(userId);
                var type = await _twoFactorService.GetTwoFactorTypeAsync(userId);

                return Ok(new {
                    IsEnabled = isEnabled,
                    Type = type
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting 2FA status");
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("recovery-codes")]
        [Authorize]
        public async Task<ActionResult> GenerateRecoveryCodes()
        {
            try
            {
                var userId = _currentUserService.GetUserId();
                var recoveryCodes = await _twoFactorService.GenerateRecoveryCodesAsync(userId);

                await _activityLoggingService.LogActivityAsync(
                    userId,
                    "2FA Recovery Codes",
                    "New recovery codes generated (old codes invalidated)");

                return Ok(new {
                    Success = true,
                    Message = "New recovery codes generated. Previous codes have been invalidated.",
                    RecoveryCodes = recoveryCodes
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating recovery codes");
                return BadRequest(new { Message = ex.Message });
            }
        }
    }
}
