using System.ComponentModel.DataAnnotations;

namespace Api_demo.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; } 
    }
}