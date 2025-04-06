using System;
using System.Security.Cryptography;
using System.Text;

public static class PasswordHashUtility
{
    public static string GenerateSalt(int size = 16)
    {
        var saltBytes = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        return Convert.ToBase64String(saltBytes); 
    }

    public static string HashPassword(string password, string salt)
    {
        var saltedPassword = salt + password;
        using (var sha256 = SHA256.Create())
        {
            var bytes = Encoding.UTF8.GetBytes(saltedPassword);
            var hash = sha256.ComputeHash(bytes);

            var sb = new StringBuilder();
            foreach (var b in hash)
            {
                sb.Append(b.ToString("x2")); 
            }
            return sb.ToString();
        }
    }
}
