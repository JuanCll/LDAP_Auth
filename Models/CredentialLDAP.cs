using System.ComponentModel.DataAnnotations;

namespace LDAPc.Models
{
    public class CredentialLDAP
    {
        [Required]
        public string? UserId { get; set; }
        [Required]
        public string? Password { get; set; }
    }
}