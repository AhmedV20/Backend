using Swashbuckle.AspNetCore.Annotations;

namespace DotnetAuth.Domain.Contracts
{
    /// <summary>
    /// Standard error response model
    /// </summary>
    /// <remarks>
    /// Used to return consistent error information across all API endpoints.
    /// </remarks>
    public class ErrorResponse
    {
        /// <summary>
        /// Error title or category
        /// </summary>
        /// <example>Authentication Error</example>
        [SwaggerSchema(Description = "Error title or category")]
        public string Titel { get; set; }

        /// <summary>
        /// HTTP status code
        /// </summary>
        /// <example>400</example>
        [SwaggerSchema(Description = "HTTP status code")]
        public int StatusCode { get; set; }

        /// <summary>
        /// Error message describing what went wrong
        /// </summary>
        /// <example>Invalid email or password</example>
        [SwaggerSchema(Description = "Human-readable error message")]
        public string Message { get; set; }

        /// <summary>
        /// Optional error code for programmatic handling
        /// </summary>
        /// <example>AUTH_001</example>
        [SwaggerSchema(Description = "Optional error code for programmatic error handling")]
        public string? ErrorCode { get; set; }

        /// <summary>
        /// Additional error details (used in development)
        /// </summary>
        /// <example>Stack trace or detailed error information</example>
        [SwaggerSchema(Description = "Additional error details (typically only in development)")]
        public string? Details { get; set; }

        /// <summary>
        /// Timestamp when the error occurred
        /// </summary>
        /// <example>2024-01-15T10:30:00Z</example>
        [SwaggerSchema(Description = "UTC timestamp when the error occurred")]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Request ID for tracking purposes
        /// </summary>
        /// <example>req_12345</example>
        [SwaggerSchema(Description = "Unique request identifier for tracking")]
        public string? RequestId { get; set; }
    }

    /// <summary>
    /// Validation error response with field-specific errors
    /// </summary>
    /// <remarks>
    /// Extended error response that includes validation errors for specific fields.
    /// </remarks>
    public class ValidationErrorResponse : ErrorResponse
    {
        /// <summary>
        /// Dictionary of field validation errors
        /// </summary>
        /// <example>{"Email": ["Email is required"], "Password": ["Password must be at least 12 characters"]}</example>
        [SwaggerSchema(Description = "Field-specific validation errors")]
        public Dictionary<string, List<string>> ValidationErrors { get; set; } = new();
    }
}
