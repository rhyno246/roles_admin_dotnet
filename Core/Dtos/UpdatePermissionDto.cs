using System.ComponentModel.DataAnnotations;

namespace Api_demo.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "UserName is required")]
        public string? UserName { get; set; } 
    }
}