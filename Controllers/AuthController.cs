using Microsoft.AspNetCore.Mvc;
using JwtAuthApi.Models;

namespace JwtAuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    // This would normally handle the OAuth flow, but we're skipping as per requirements
    // We'll just include a placeholder for the oauth endpoint
    
    // [HttpPost("oauth")]
    // public IActionResult OAuth([FromQuery] string code)
    // {
    //     // Normally this would handle the OAuth flow, but we're skipping as per requirements
    //     return BadRequest("OAuth flow not implemented as per requirements");
    // }
}