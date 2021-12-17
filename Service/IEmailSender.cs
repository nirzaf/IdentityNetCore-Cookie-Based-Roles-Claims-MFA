using System.Threading.Tasks;

namespace IdentityNetCore.Service
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string fromAddress, string toAddress, string subject, string message);
    }
}
