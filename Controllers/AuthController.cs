using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuthApi.Controllers
{
    [ApiController]
    [Authorize]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly string _jwtSecret;

        public AuthController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") ??
                throw new InvalidOperationException("Missing DB connection string");
            _jwtSecret = configuration["JwtSettings:SecretKey"] ??
                throw new InvalidOperationException("JWT Secret Key is missing");
        }

        [HttpPost("signup")]
        [AllowAnonymous]
        public IActionResult SignUp([FromBody] LoginRequest loginRequest)
        {
            if (loginRequest == null || string.IsNullOrEmpty(loginRequest.Username)
                || string.IsNullOrEmpty(loginRequest.Password))
            {
                return BadRequest("Username and Password are required");
            }

            try
            {
                using var conn = new NpgsqlConnection(_connectionString);
                conn.Open();
            var checkCmd = new NpgsqlCommand(@"SELECT COUNT(*) FROM user_account 
                WHERE username = @username", 
                conn);
            checkCmd.Parameters.AddWithValue("username", 
                loginRequest.Username);
            long? userCount = (long?)checkCmd.ExecuteScalar();
            if (userCount > 0)
            {
                return Conflict("Username already exists");
            }
            
            string salt = PasswordHashUtility.GenerateSalt();
            string hashedPassword = PasswordHashUtility.HashPassword(loginRequest.Password, salt);
            var insertCmd = new NpgsqlCommand(
            @"INSERT INTO user_account(username, password, salt) 
                    VALUES (@username, 
                    @password, 
                    @salt)", 
                    conn);
            insertCmd.Parameters.AddWithValue("username", loginRequest.Username);
            insertCmd.Parameters.AddWithValue("password", hashedPassword);
            insertCmd.Parameters.AddWithValue("salt", salt);
            insertCmd.Parameters.AddWithValue("email", (object)DBNull.Value); 
            insertCmd.Parameters.AddWithValue("phone_number", (object)DBNull.Value); 
            insertCmd.ExecuteNonQuery();
            return Ok("User registered successfully");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error occurred during signup: {ex.Message}");
            }
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            if (loginRequest == null || string.IsNullOrEmpty(loginRequest.Username)
            || string.IsNullOrEmpty(loginRequest.Password))
            {
            return BadRequest("Username and Password are required");
            }

        try
        {
            using var conn = new NpgsqlConnection(_connectionString);
            conn.Open();
            var cmd = new NpgsqlCommand(
                "SELECT password, salt FROM user_account WHERE username = @username", conn);
            cmd.Parameters.AddWithValue("username", loginRequest.Username);
            using var reader = cmd.ExecuteReader();

            if (!reader.Read())
            {
                return Unauthorized("Invalid username or password");
            }

            string storedHashedPassword = reader.GetString(0);
            string storedSalt = reader.GetString(1);
            reader.Close();

            string hashedInputPassword = PasswordHashUtility.
                HashPassword(loginRequest.Password, storedSalt);
            if (!hashedInputPassword.Equals(storedHashedPassword, 
                StringComparison.OrdinalIgnoreCase))
            {
                return Unauthorized("Invalid username or password");
            }

            // Generate JWT Token
            string token = GenerateJwtToken(loginRequest.Username);

            // Set the JWT token in an HttpOnly, Secure Cookie
            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true,  
                Secure = true,    
                SameSite = SameSiteMode.Strict,  
                Expires = DateTime.UtcNow.AddHours(3)  
            });

            return Ok("Login successful");
            }
            catch (Exception ex)
            {
            return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }


        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: "Issuer",
                audience: "Audience",
                claims: claims,
                expires: DateTime.UtcNow.AddHours(3),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class LoginRequest
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
}