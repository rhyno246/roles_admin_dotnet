using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Api_demo.Core.Dtos;
using Api_demo.Core.OrtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Api_demo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        //Route for Seeding role data
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles () 
        {
            bool isOwnerExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isUserExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);
            bool isAdminExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            if(isOwnerExists && isAdminExists && isUserExists)
                return Ok("Role Seeding is Already success");
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            return Ok("Role Seeding success");
        }

        //Route for Register 
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var isExistsUser =  await _userManager.FindByEmailAsync(registerDto.Email);
            if(isExistsUser != null) {
                return BadRequest("Email is already exists");
            }
            IdentityUser newUser = new IdentityUser()
            {
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp =  Guid.NewGuid().ToString(),
            };
            var createUserResult = await _userManager.CreateAsync(newUser , registerDto.Password);
            if(!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Because : ";
                foreach(var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return BadRequest(errorString);
            }
            await _userManager.AddToRoleAsync(newUser , StaticUserRoles.USER);
            return Ok("User Created Success");
        }

        // Route for login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login ([FromBody] LoginDto loginDto) 
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if(user == null)
            {
                return Unauthorized("Invalid Credentials");
            }
            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if(!isPasswordCorrect)
            {
                return Unauthorized("Password not match");
            }
            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name , user.UserName),
                new Claim(ClaimTypes.Email , user.Email),
                new Claim(ClaimTypes.NameIdentifier , user.Id),
                new Claim("JWTID" , Guid.NewGuid().ToString())
            };

            foreach(var userRole in userRoles )
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);
            return Ok(token);
        }

        [HttpGet]
        [Route("GetUsersRole")]
        [Authorize(Roles = StaticUserRoles.USER)]
        public IActionResult GetUsersRole ()
        {
            return Ok();
        }

        [HttpGet]
        [Route("GetOwnerRole")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public IActionResult GetOwnerRole ()
        {
            return Ok();
        }

        [HttpGet]
        [Route("GetAdminRole")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public IActionResult GetAdminRole ()
        {
            return Ok();
        }

        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var tokenObject = new JwtSecurityToken(
                issuer : _configuration["JWT:ValidIssuer"],
                audience : _configuration["JWT:ValidAudience"],
                expires : DateTime.Now.AddHours(1),
                claims : claims,
                signingCredentials : new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
            );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin ([FromBody] UpdatePermissionDto updatePermissionDto) 
        {
            var user = await _userManager.FindByEmailAsync(updatePermissionDto.Email);
            if(user == null)
            {
                return BadRequest("Invalid Email");
            }
            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            return Ok("User update status success");
        }
    }
}
