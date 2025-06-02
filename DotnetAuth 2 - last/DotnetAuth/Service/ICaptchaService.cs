using System.Threading.Tasks;

namespace DotnetAuth.Service
{
    public interface ICaptchaService
    {
        Task<bool> VerifyCaptchaAsync(string captchaToken);
    }
}
