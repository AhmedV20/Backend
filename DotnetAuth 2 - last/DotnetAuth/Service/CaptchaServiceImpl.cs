using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DotnetAuth.Service
{
    public class CaptchaServiceImpl : ICaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<CaptchaServiceImpl> _logger;
        private readonly HttpClient _httpClient;

        public CaptchaServiceImpl(
            IConfiguration configuration,
            ILogger<CaptchaServiceImpl> logger,
            IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient("CaptchaClient");
        }

        public async Task<bool> VerifyCaptchaAsync(string captchaToken)
        {
            try
            {
                // For testing purposes, accept Google's test token
                if (captchaToken == "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI")
                {
                    _logger.LogWarning("Using Google's test reCAPTCHA token. This should not be used in production.");
                    return true;
                }

                // Get the secret key from configuration
                var secretKey = _configuration["ReCaptcha:SecretKey"];
                if (string.IsNullOrEmpty(secretKey))
                {
                    _logger.LogError("reCAPTCHA secret key is not configured");
                    return false;
                }

                // Prepare the request to Google's reCAPTCHA verification API
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("secret", secretKey),
                    new KeyValuePair<string, string>("response", captchaToken)
                });

                // Send the request
                var response = await _httpClient.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
                var responseContent = await response.Content.ReadAsStringAsync();

                // Parse the response
                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                var captchaResponse = JsonSerializer.Deserialize<CaptchaResponse>(responseContent, options);

                // Check if the CAPTCHA verification was successful
                if (captchaResponse != null && captchaResponse.Success)
                {
                    return true;
                }
                else
                {
                    _logger.LogWarning("CAPTCHA verification failed: {ErrorCodes}", 
                        captchaResponse?.ErrorCodes != null ? string.Join(", ", captchaResponse.ErrorCodes) : "Unknown error");
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying CAPTCHA token");
                return false;
            }
        }

        private class CaptchaResponse
        {
            public bool Success { get; set; }
            public string[] ErrorCodes { get; set; }
            public string ChallengeTs { get; set; }
            public string Hostname { get; set; }
        }
    }
}
