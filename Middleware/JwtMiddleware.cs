using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SimpleNewsSystem.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IConfiguration _configuration;

        public JwtMiddleware(RequestDelegate next, IConfiguration configuration)
        {
            _next = next;
            _configuration = configuration;
        }

        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Cookies["Authorization"];

            if (token != null)
            {
                var secretKey = _configuration.GetValue<string>("Jwt:Key");
                var issuer = _configuration.GetValue<string>("Jwt:Issuer");
                var audience = _configuration.GetValue<string>("Jwt:Audience");

                AttachUserToContext(context, token, secretKey ?? throw new ArgumentNullException(nameof(secretKey)));

            }
            else
            {
                Console.WriteLine("Token não encontrado na requisição.");
            }

            await _next(context);
        }

        private void AttachUserToContext(HttpContext context, string token, string secretKey)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(secretKey);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero // Remove qualquer diferença de tempo entre o servidor e o token
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                 var email = jwtToken.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
                 var role = jwtToken.Claims.FirstOrDefault(x => x.Type == "role")?.Value;

                if (!string.IsNullOrEmpty(email))
                {
                    // Adicione o email do usuário ao contexto da requisição
                    context.Items["Email"] = email;
                }
                else
                {
                    Console.WriteLine("O token JWT não contém uma reivindicação de email.");
                }

                 if (!string.IsNullOrEmpty(role))
                {
                    // Adicione a role do usuário ao contexto da requisição
                    context.Items["Role"] = role;
                }
                else
                {
                    Console.WriteLine("O token JWT não contém uma reivindicação de role.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro ao validar o token JWT: " + ex.Message);
            }
        }

    }

    public static class JwtMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtMiddleware>();
        }
    }
}
