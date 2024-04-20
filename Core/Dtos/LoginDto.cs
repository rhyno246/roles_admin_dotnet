using System.ComponentModel.DataAnnotations;
namespace Api_demo.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; } 

        [Required(ErrorMessage = "PassWord is required")]
        public string? Password { get; set; }
    }
}