using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SimpleNewsSystem.Models;

namespace SimpleNewsSystem.Filters
{
    public class AdminAuthorizationFilter : IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;

            if (user?.Identity == null || !user.Identity.IsAuthenticated)
            {
                context.Result = new RedirectToActionResult("Login", "User", null);
                return;
            }

            if (!user.IsInRole("Admin"))
            {
                context.Result = new ForbidResult();
                return;
            }
        }
    }
}
