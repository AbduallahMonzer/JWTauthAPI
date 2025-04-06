using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Collections.Generic;
using JwtAuthApi.Models;

namespace JwtAuthApi.Controllers
{
    [ApiController]
    [Route("api")]
    public class UserController : ControllerBase
    {
        private readonly string _connectionString;

        public UserController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException("Missing DB connection string");
        }

        // POST: api/new - Complete user profile
    [HttpPost("new")]
public IActionResult CompleteUserProfile([FromBody] User user)
{
    if (user == null || string.IsNullOrEmpty(user.Username) 
        || string.IsNullOrEmpty(user.Password))
    {
        return BadRequest("Username and Password are required");
    }

    NpgsqlConnection? conn = null;
    try
    {
        conn = new NpgsqlConnection(_connectionString);
        conn.Open();

        var checkCmd = new NpgsqlCommand(
            @"SELECT COUNT(*) FROM user_account 
            WHERE username = @username",
            conn);
        checkCmd.Parameters.AddWithValue("username", user.Username);
        long? userCount = checkCmd.ExecuteScalar() as long?;

        if (userCount == 0)
        {
            return NotFound("User not found. Please sign up first.");
        }

        var updateCmd = new NpgsqlCommand(
            @"UPDATE user_account SET
            password = @password, 
            email = @email,
            phone_number = @phone_number,
            role = @role
            WHERE username = @username", conn);
        updateCmd.Parameters.AddWithValue("password", 
            string.IsNullOrEmpty(user.Password) ? DBNull.Value : (object)user.Password!);
        updateCmd.Parameters.AddWithValue("email", 
            string.IsNullOrEmpty(user.Email) ? DBNull.Value : (object)user.Email!);
        updateCmd.Parameters.AddWithValue("phone_number",   
            string.IsNullOrEmpty(user.PhoneNumber) ? DBNull.Value : (object)user.PhoneNumber!);
        updateCmd.Parameters.AddWithValue("role", 
            string.IsNullOrEmpty(user.Role) ? DBNull.Value : (object)user.Role!);
        updateCmd.Parameters.AddWithValue("username", user.Username);

        int rowsAffected = updateCmd.ExecuteNonQuery();
        if (rowsAffected == 0)
        {
            return StatusCode(500, "Failed to update user profile.");
        }

        return Ok(new
        {
            Message = "User profile updated successfully.",
            Username = user.Username,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            Role = user.Role
        });
    }
    catch (Exception ex)
    {
        return StatusCode(500, $"Internal server error: {ex.Message}");
    }
    finally
    {
        conn?.Close();
    }
}


        // GET: api/list_users - Get all users
        [HttpGet("list_users")]
        public IActionResult GetUsers()
        {
            NpgsqlConnection? conn = null;
            try
            {
                conn = new NpgsqlConnection(_connectionString);
                conn.Open();

                var cmd = new NpgsqlCommand(@"SELECT id, 
                username,
                email,
                phone_number,
                role
                FROM user_account", conn);
                var reader = cmd.ExecuteReader();

                var users = new List<User>();

                while (reader.Read())
                {
                    users.Add(new User
                    {
                        Id = reader.GetInt32(0),
                        Username = reader.GetString(1),
                        Email = reader.IsDBNull(2) ? null : reader.GetString(2),
                        PhoneNumber = reader.IsDBNull(3) ? null : reader.GetString(3),
                        Role = reader.IsDBNull(4) ? null : reader.GetString(4)
                    });
                }

                return Ok(users);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
            finally
            {
                if (conn != null)
                    conn.Close();
            }
        }

        // POST: api/update - we will use in OAuth
        /* [HttpPost("update")]
        public IActionResult UpdateUser([FromBody] User user)
        {
            if (user == null || user.Id <= 0)
            {
                return BadRequest("User ID is required for update");
            }
            NpgsqlConnection? conn = null;
            try
            {
                conn = new NpgsqlConnection(_connectionString);
                conn.Open();

                var query = @"UPDATE user_account SET
                    username = @username,
                    email = @email,
                    phone_number = @phone_number,
                    role = @role
                WHERE id = @id";

                var updateCmd = new NpgsqlCommand(query, conn);
                updateCmd.Parameters.Add("username", 
                    NpgsqlTypes.NpgsqlDbType.Varchar).Value = user.Username;
                updateCmd.Parameters.Add("email", 
                    NpgsqlTypes.NpgsqlDbType.Varchar).Value = user.Email;
                updateCmd.Parameters.Add("phone_number", 
                    NpgsqlTypes.NpgsqlDbType.Varchar).Value = user.PhoneNumber;
                updateCmd.Parameters.Add("role", 
                    NpgsqlTypes.NpgsqlDbType.Varchar).Value = user.Role;
                updateCmd.Parameters.Add("id", 
                    NpgsqlTypes.NpgsqlDbType.Integer).Value = user.Id;

                int rowsAffected = updateCmd.ExecuteNonQuery();
                if (rowsAffected == 0)
                    return NotFound("User not found");

                return Ok(new { 
                    Id = user.Id, 
                    Username = user.Username, 
                    Email = user.Email, 
                    PhoneNumber = user.PhoneNumber, 
                    Role = user.Role 
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
            finally
            {
                if (conn != null)
                    conn.Close();
            }
        }
            */
        // POST: api/refresh_token - Refresh JWT token
        [HttpPost("refresh_token")] 
        public IActionResult RefreshToken()
        {
            return Unauthorized("JWT refresh logic goes here");
        }
    }
}
