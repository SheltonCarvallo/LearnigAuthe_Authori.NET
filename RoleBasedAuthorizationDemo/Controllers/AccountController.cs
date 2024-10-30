using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RoleBasedAuthorizationDemo.Authentication;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace RoleBasedAuthorizationDemo.Controllers;
//primary constructor syntax
[ApiController]
[Route("[controller]")]
public class
    AccountController(UserManager<AppUser> userManager, IConfiguration configuration, SignInManager<AppUser> signInManager) //Directly DI using userManager and configuration
    : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] AddOrUpdateAppUserModel model)
    {
        return await RegisterUserWithRole(model, AppRoles.User);
    }

    [HttpPost("register-admin")]
    public async Task<IActionResult> RegisterAdmin([FromBody] AddOrUpdateAppUserModel model)
    {
        return await RegisterUserWithRole(model, AppRoles.Administrator);
    }

    [HttpPost("register-vip")]
    public async Task<IActionResult> RegisterVip([FromBody] AddOrUpdateAppUserModel model)
    {
        return await RegisterUserWithRole(model, AppRoles.VipUser);
    }


    private async Task<IActionResult> RegisterUserWithRole(AddOrUpdateAppUserModel model, string roleName)
    {
        if (ModelState.IsValid) //What is ModelState?
        {
            AppUser? existedUser = await userManager.FindByNameAsync(model.UserName);
            if (existedUser != null)
            {
                ModelState.AddModelError("", "User name is already taken");
                return BadRequest(ModelState);
            }

            // Create a new user project
            AppUser user = new AppUser()
            {
                UserName = model.UserName,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };
            // Try to save the user
            IdentityResult userResult = await userManager.CreateAsync(user, model.Password);
            // Add the user to the role
            IdentityResult roleResult = await userManager.AddToRoleAsync(user, roleName);
            // If the user is successfully created return Ok
            if (userResult.Succeeded && roleResult.Succeeded)
            {
                AppUser? createdUser = await userManager.FindByNameAsync(model.UserName);
                Task<string?> token = GenerateToken(createdUser!, model.UserName);
                return Ok(new { token });
            }

            // If there are any errors, add them to th ModelState Object
            // and return the error to the client
            foreach (IdentityError error in
                     userResult.Errors) //TODO: I have to check this, I mean why there is a foreach loop
            {
                ModelState.AddModelError("", error.Description);
            }

            foreach (IdentityError error in roleResult.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
        }

        // If we got this far. something failed redisplay form
        return BadRequest(ModelState);
    }

    // Create a Login action to validate the user credentials and generate the JWT token
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        // Get the secret in the configuration

        // Check if the model is valid
        if (ModelState.IsValid)
        {
            AppUser? user = await userManager.FindByNameAsync(model.UserName);
            if (user != null)
            {
                SignInResult result = await signInManager.CheckPasswordSignInAsync(user, model.Password, true);
                if (result.Succeeded)
                {
                    Task<string?> token = GenerateToken(user, model.UserName);
                    return Ok(new { token });
                }
                /* if (await userManager.CheckPasswordAsync(user, model.Password))
                {
                    Task<string?> token = GenerateToken(user, model.UserName);
                    return Ok(new { token });
                }*/
            }

            // If the user is not found, display an error message
            ModelState.AddModelError("", "Invalid username or password");
        }

        return BadRequest(ModelState);
    }

    private async Task<string?> GenerateToken(AppUser user, string userName)
    {
        string? secret = configuration["JwtConfig:Secret"];
        string? issuer = configuration["JwtConfig:ValidIssuer"];
        string? audience = configuration["JwtConfig:ValidAudiences"];
        if (secret is null || issuer is null || audience is null)
        {
            throw new ApplicationException("Jwt is not set in the configuration");
        }

        SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

        IList<string> userRoles = await userManager.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userName)
        };
        claims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));
        SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        SecurityToken? securityToken = tokenHandler.CreateToken(tokenDescriptor);

        //var jwtToken = new JwtSecurityToken(
        //    issuer: issuer,
        //    audience: audience,
        //    claims: new[]{
        //        new Claim(ClaimTypes.Name, userName)
        //    },
        //    expires: DateTime.UtcNow.AddDays(1),
        //    signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature)
        //);
        string? token = tokenHandler.WriteToken(securityToken);
        return token;
    }
}