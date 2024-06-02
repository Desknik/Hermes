using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace SimpleNewsSystem.Filters
{
    public class AdminAuthorizationFilter : IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var token = context.HttpContext.Request.Cookies["Authorization"];

            if (string.IsNullOrEmpty(token))
            {
                context.Result = new RedirectToActionResult("Login", "User", null);
                return;
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                // Verifica se o email está presente no token
                var userEmailClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "email")?.Value;
                if (string.IsNullOrEmpty(userEmailClaim))
                {
                    context.Result = new ForbidResult();
                    return;
                }

                // Verifica se o papel do usuário é "Admin" no token
                var userRoleClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "role")?.Value;
                if (userRoleClaim != "Admin")
                {
                    context.Result = new ForbidResult();
                    return;
                }
            }
            catch (Exception)
            {
                context.Result = new ForbidResult();
                return;
            }
        }
    }
}
