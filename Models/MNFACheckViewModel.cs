using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class MNFACheckViewModel
    {
        [Required]
        public string Code { get; set; }

    }
}
