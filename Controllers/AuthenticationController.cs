using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthLawan.Models;
using AuthLawan.Models.DTOs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthLawan.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager; // this is the service that will help us create users and save them to the database without writing any SQL code or using DbSets 
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
          IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto){
            if(ModelState.IsValid){
                var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);
                if(existingUser != null){
                    return BadRequest(new AuthResult{
                        Errors = new List<string>() {
                            "Email already in use"
                        },
                        Result = false
                    });
                }
                // create a new user object
                var new_user = new IdentityUser() {
                    Email = requestDto.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = requestDto.Name
                };

                // save the user object to the database
                var isCreated = await _userManager.CreateAsync(new_user, requestDto.Password);
                if(isCreated.Succeeded){
                    // generate jwt token
                    var token = GenerateJwtToken(new_user);
                    return Ok(new AuthResult{
                        Result = true,
                        Token = token
                    });
                } else {
                    return BadRequest(new AuthResult{
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                        Result = false
                    });
                }
            }
            return BadRequest();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto){
            if(ModelState.IsValid){
                // check if the user with the same email exists
                var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);
                if(existingUser == null){
                    return BadRequest(new AuthResult{
                        Errors = new List<string>() {
                            "Invalid authentication request"
                        },
                        Result = false
                    });
                }

                // check if the user has input the correct password
                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, requestDto.Password);
                if(!isCorrect){
                    return BadRequest(new AuthResult{
                        Errors = new List<string>() {
                            "Invalid authentication request"
                        },
                        Result = false
                    });
                }

                // generate jwt token
                var token = GenerateJwtToken(existingUser);
                // var refreshToken = GenerateRefreshToken();
                return Ok(new AuthResult{
                    Result = true,
                    Token = token,
                    // RefreshToken = refreshToken
                });
            }
            return BadRequest(new AuthResult{
                Errors = new List<string>() {
                    "Invalid payload"
                },
                Result = false
            });
        }


        // Get user profile information [Authorize]
         [HttpGet]
        [Route("Profile")]
        [Authorize] // Require authentication for this endpoint
        public async Task<IActionResult> GetUserProfile(){
            try
            {
                // Get the authenticated user's information from the token
                var userId = User.FindFirstValue("Id"); // Retrieve user ID from claims
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    // return NotFound(new AuthResult
                    // {
                    //     Errors = new List<string> { "User not found" },
                    //     Result = false
                    // });
                }

                // Return the user profile information
                var userProfile = new UserResponseDto
                {
                    Email = user.Email,
                    Name = user.UserName,
                };

                return Ok(userProfile);
            }
            catch (Exception ex)
            {
                // Handle exceptions and return an appropriate response
                return StatusCode(500, new AuthResult
                {
                    Errors = new List<string> { $"An error occurred while processing the request {ex.Message}" },
                    Result = false
                });
            }
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:Secret"]); // we need to convert the secret key to a byte array

            // Token Descriptor
            var tokenDescriptor = new  SecurityTokenDescriptor(){
                    Subject = new ClaimsIdentity(new [] {
                        new Claim("Id", user.Id.ToString()),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                    }),
                    Expires = DateTime.UtcNow.AddHours(6),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor); // we nee to convert this token to a string so we can return it to the client
            return jwtTokenHandler.WriteToken(token);
    }

    // refresh token
    // private string GenerateRefreshToken()
    // {
    //     var randomNumber = new byte[32];
    //     using(var rng = RandomNumberGenerator.Create()){
    //         rng.GetBytes(randomNumber);
    //         return Convert.ToBase64String(randomNumber);
    //     }
    // }
    // logout


}
}