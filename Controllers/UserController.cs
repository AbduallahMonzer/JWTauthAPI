using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using JwtAuthApi.Models;
using Microsoft.Extensions.Options;

namespace JwtAuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly JwtSettings _jwtSettings;

    public UserController(AppDbContext context, IOptions<JwtSettings> jwtSettings)
    {
        _context = context;
        _jwtSettings = jwtSettings.Value;

        // Validate configuration
        if (string.IsNullOrEmpty(_jwtSettings.SecretKey))
        {
            throw new InvalidOperationException("JWT Secret Key is not configured");
        }
    }

    [Authorize]
    [HttpGet("list_users")]
    public async Task<IActionResult> ListUsers()
    {
        var users = await _context.Users.ToListAsync();
        return Ok(users);
    }

    [Authorize]
    [HttpPost("new")]
    public async Task<IActionResult> CreateUser([FromBody] User user)
    {
        if (user == null)
            return BadRequest("User object is required");

        // Validate required fields
        if (string.IsNullOrEmpty(user.Email))
            return BadRequest("Email is required");

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(user);
    }

    [Authorize]
    [HttpPost("update")]
    public async Task<IActionResult> UpdateUser([FromBody] User user)
    {
        if (user == null || user.Id == 0)
            return BadRequest("Valid user ID is required");

        var existingUser = await _context.Users.FindAsync(user.Id);
        if (existingUser == null)
            return NotFound("User not found");

        // Update properties
        if (!string.IsNullOrEmpty(user.Email))
            existingUser.Email = user.Email;
            
        if (!string.IsNullOrEmpty(user.FullName))
            existingUser.FullName = user.FullName;
            
        if (!string.IsNullOrEmpty(user.PhoneNumber))
            existingUser.PhoneNumber = user.PhoneNumber;

        await _context.SaveChangesAsync();

        return Ok(existingUser);
    }

    [HttpPost("refresh_token")]
    [Authorize]
    public IActionResult RefreshToken()
    {
        var userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
        if (string.IsNullOrEmpty(userEmail))
            return Unauthorized("Invalid token claims");

        var token = GenerateJwtToken(userEmail);
        Response.Cookies.Append("jwt", token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddHours(3) // Match token expiration
        });

        return Ok(new { message = "Token refreshed successfully" });
    }

    private string GenerateJwtToken(string email)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            // Add other claims as needed
        };

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(3),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}