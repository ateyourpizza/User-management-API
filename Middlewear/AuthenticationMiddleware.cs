using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public AuthenticationMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.Headers.ContainsKey("Authorization"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var token = context.Request.Headers["Authorization"].ToString().Split(" ").Last();
        if (!ValidateToken(token))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        await _next(context);
    }

    private bool ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = System.Text.Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false
            }, out SecurityToken validatedToken);
        }
        catch
        {
            return false;
        }
        return true;
    }
}

public static class AuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AuthenticationMiddleware>();
    }
}
