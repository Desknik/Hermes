using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

public class ClaimsLoggerMiddleware
{
    private readonly RequestDelegate _next;

    public ClaimsLoggerMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        var userEmail = context.User.FindFirst(ClaimTypes.Name)?.Value;

        if (!string.IsNullOrEmpty(userEmail))
        {
            // Aqui você pode adicionar log ou imprimir as claims do usuário
            System.Console.WriteLine($"Usuário logado com email: {userEmail}");
        }else{
            System.Console.WriteLine("Usuário não está logado");
        }

        await _next(context);
    }
}
