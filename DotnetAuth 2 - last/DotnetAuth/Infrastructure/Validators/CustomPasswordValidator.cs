using Microsoft.AspNetCore.Identity;
using System.Text.RegularExpressions;

namespace DotnetAuth.Infrastructure.Validators
{
    public class CustomPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var errors = new List<IdentityError>();

            if (password.Length < 12)
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordTooShort",
                    Description = "Password must be at least 12 characters long"
                });
            }

            if (!password.Any(char.IsUpper))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordRequiresUpper",
                    Description = "Password must contain at least one uppercase letter"
                });
            }

            if (!password.Any(char.IsLower))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordRequiresLower",
                    Description = "Password must contain at least one lowercase letter"
                });
            }

            if (!password.Any(char.IsDigit))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordRequiresDigit",
                    Description = "Password must contain at least one number"
                });
            }

            if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
            {
                errors.Add(new IdentityError
                {
                    Code = "PasswordRequiresNonAlphanumeric",
                    Description = "Password must contain at least one special character"
                });
            }

            var commonPatterns = new[]
            {
                @"12345",
                @"qwerty",
                @"password",
                @"admin",
                @"user"
            };

            foreach (var pattern in commonPatterns)
            {
                if (password.ToLower().Contains(pattern))
                {
                    errors.Add(new IdentityError
                    {
                        Code = "CommonPassword",
                        Description = $"Password contains a common pattern '{pattern}' that is not allowed"
                    });
                }
            }

            foreach (var group in password.GroupBy(c => c))
            {
                if (group.Count() > 3)
                {
                    errors.Add(new IdentityError
                    {
                        Code = "RepeatedCharacters",
                        Description = $"Password contains too many repeated characters"
                    });
                    break;
                }
            }

            if (Regex.IsMatch(password, @"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz", RegexOptions.IgnoreCase))
            {
                errors.Add(new IdentityError
                {
                    Code = "SequentialCharacters",
                    Description = "Password contains sequential characters that are not allowed"
                });
            }

            if (Regex.IsMatch(password, @"qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm", RegexOptions.IgnoreCase))
            {
                errors.Add(new IdentityError
                {
                    Code = "KeyboardPattern",
                    Description = "Password contains keyboard patterns that are not allowed"
                });
            }

            return errors.Count == 0 ? 
                IdentityResult.Success : 
                IdentityResult.Failed(errors.ToArray());
        }
    }
}