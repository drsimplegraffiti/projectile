using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthLawan.Data;
using AuthLawan.Models;
using AuthLawan.Models.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthLawan.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager; // this is the service that will help us create users and save them to the database without writing any SQL code or using DbSets 
        private readonly IConfiguration _configuration;
        private readonly ApiDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public object Timespan { get; private set; }

        public AuthenticationController(UserManager<IdentityUser> userManager,
          IConfiguration configuration,
          ApiDbContext context,
          TokenValidationParameters tokenValidationParameters)
        {
            _userManager = userManager;
            _configuration = configuration;
            _context = context;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);
                if (existingUser != null)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>() {
                            "Email already in use"
                        },
                        Result = false
                    });
                }
                // create a new user object
                var new_user = new IdentityUser()
                {
                    Email = requestDto.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = requestDto.Name
                };

                // save the user object to the database
                var isCreated = await _userManager.CreateAsync(new_user, requestDto.Password);
                if (isCreated.Succeeded)
                {
                    // generate jwt token
                    var token = await GenerateJwtToken(new_user);
                    
                    return Ok(token);

                }
                else
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                        Result = false
                    });
                }
            }
            return BadRequest();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto)
        {
            if (ModelState.IsValid)
            {
                // check if the user with the same email exists
                var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);
                if (existingUser == null)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>() {
                            "Invalid authentication request"
                        },
                        Result = false
                    });
                }

                // check if the user has input the correct password
                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, requestDto.Password);
                if (!isCorrect)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>() {
                            "Invalid authentication request"
                        },
                        Result = false
                    });
                }

                // generate jwt token
                var token = await GenerateJwtToken(existingUser);
                return Ok(token);
            }
            return BadRequest(new AuthResult
            {
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
        public async Task<IActionResult> GetUserProfile()
        {
            try
            {
                // Get the authenticated user's information from the token
                var userId = User.FindFirstValue("Id"); // Retrieve user ID from claims
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return NotFound(new AuthResult
                    {
                        Errors = new List<string> { "User not found" },
                        Result = false
                    });
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

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:Secret"]); // we need to convert the secret key to a byte array

            // Token Descriptor
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[] {
                        new Claim("Id", user.Id.ToString()),
                        new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                        new Claim(JwtRegisteredClaimNames.Email, user.Email),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString()),
                    }),
                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor); // we nee to convert this token to a string so we can return it to the client
            var jwtToken = jwtTokenHandler.WriteToken(token);
            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomStringGeneration()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

           var authResult = new AuthResult
            {
                Result = true,
                Token = jwtToken,
                RefreshToken = refreshToken.Token
            };

            return authResult;
            

        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = VerifyAndGenerateToken(tokenRequest);
                if (result == null)
                {
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>(){
                    "Invalid token"
                },
                        Result = false
                    });
                }

                return Ok(new AuthResult
                {
                    Result = true,
                    Token = result.Result.Token,
                    RefreshToken = result.Result.RefreshToken
                });

            }

            return BadRequest(new AuthResult
            {
                Errors = new List<string>(){
                    "Invalid payload"
                },
                Result = false
            });
        }

        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            try
            {
                _tokenValidationParameters.ValidateLifetime = false; // we are disabling the lifetime validation
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                        return null;
                }

                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                Console.WriteLine("utcExpiryDate: " + utcExpiryDate);
                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                Console.WriteLine("expiryDate: " + expiryDate);
                if (expiryDate > DateTime.Now)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Expired token"
                        }
                    };

                var storedRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedRefreshToken == null)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Invalid token"
                        }
                    };

                if (storedRefreshToken.IsUsed)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Token has been used"
                        }
                    };

                if (storedRefreshToken.IsRevoked)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Token has been revoked"
                        }
                    };

                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if (storedRefreshToken
                    .JwtId != jti)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Token doesn't match"
                        }
                    };

                if (storedRefreshToken.ExpiryDate < DateTime.UtcNow)
                    return new AuthResult
                    {
                        Result = false,
                        Errors = new List<string>(){
                            "Token has expired, user needs to relogin"
                        }
                    };

                storedRefreshToken.IsUsed = true;
                _context.RefreshTokens.Update(storedRefreshToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
                return await GenerateJwtToken(dbUser);

            }
            catch (Exception)
            {

                return new AuthResult
                {
                    Result = false,
                    Errors = new List<string>(){
                        "Server error occured"
                    }
                };
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
            return dateTimeVal;
        }

        private string RandomStringGeneration()
        {
            var randomNumber = new byte[32];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }


        // revoke token
        [HttpPost("revoke-token")]
        [Authorize]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest revokeTokenRequest)
        {
            try
            {
                var userId = User.FindFirstValue("Id"); // Retrieve user ID from claims
                var storedRefreshToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == revokeTokenRequest.RefreshToken);

                if (storedRefreshToken == null)
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>(){
                    "Invalid token"
                },
                        Result = false
                    });

                if (storedRefreshToken.UserId != userId)
                    return BadRequest(new AuthResult
                    {
                        Errors = new List<string>(){
                    "Invalid token"
                },
                        Result = false
                    });

                storedRefreshToken.IsRevoked = true;
                _context.RefreshTokens.Update(storedRefreshToken);
                await _context.SaveChangesAsync();

                return Ok(new AuthResult
                {
                    Result = true,

                });
            }
            catch (Exception)
            {
                return StatusCode(500, new AuthResult
                {
                    Errors = new List<string> { "An error occurred while processing the request" },
                    Result = false
                });
            }
        }


    }
}