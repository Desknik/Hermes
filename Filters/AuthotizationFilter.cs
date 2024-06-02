using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace SimpleNewsSystem.Filters
{
    public class AuthorizationFilter : IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var userEmail = context.HttpContext.Items["Email"] as string;

            if (!string.IsNullOrEmpty(userEmail))
            {
                context.Result = new RedirectToActionResult("Login", "User", null);
                return;
            }
        }
    }
}
