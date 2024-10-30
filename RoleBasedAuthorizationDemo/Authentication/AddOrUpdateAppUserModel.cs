using System.ComponentModel.DataAnnotations;

namespace RoleBasedAuthorizationDemo.Authentication;

public class AddOrUpdateAppUserModel
{
    [Required(ErrorMessage = "username is required")]
    public string UserName { get; set; } = string.Empty;
   
    [EmailAddress] //If I am not mistaken this property is used to the Email property meets the email standard
    [Required(ErrorMessage = "Email is required")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;
}