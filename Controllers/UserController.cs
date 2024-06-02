using Microsoft.AspNetCore.Mvc;
using SimpleNewsSystem.Data;
using SimpleNewsSystem.Models;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;


using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace SimpleNewsSystem.Controllers
{
    public class UserController : Controller
    {
         private readonly ApplicationDbContext _context;
        private readonly string _jwtKey;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;

        public UserController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _jwtKey = configuration["Jwt:Key"] ?? throw new ArgumentNullException("JWT Key is not configured properly in appsettings.json.");
            _jwtIssuer = configuration["Jwt:Issuer"] ?? throw new ArgumentNullException("JWT Issuer is not configured properly in appsettings.json.");
            _jwtAudience = configuration["Jwt:Audience"] ?? throw new ArgumentNullException("JWT Audience is not configured properly in appsettings.json.");
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Register(User user)
        {
            if (ModelState.IsValid)
            {
                // Verifica se o e-mail já está em uso
                if (_context.Users.Any(u => u.email == user.email))
                {
                    ModelState.AddModelError("Email", "E-mail já está em uso.");
                    return View(user);
                }

                // Criptografa a senha antes de salvar no banco de dados
                user.password = EncryptPassword(user.password);

                _context.Users.Add(user);
                _context.SaveChanges();
                return RedirectToAction("Login");
            }
            return View(user);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(User user)
    {
        var hashedPassword = EncryptPassword(user.password);
        var existingUser = _context.Users.FirstOrDefault(u => u.email == user.email && u.password == hashedPassword);

        if (existingUser != null)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.email),
                new Claim(ClaimTypes.Role, existingUser.is_admin ? "Admin" : "User")
            };

            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _jwtIssuer,
                Audience = _jwtAudience,
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            Response.Cookies.Append("Authorization", tokenString, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            return RedirectToAction("Index", "Home");
        }
        else
        {
            ModelState.AddModelError("", "Credenciais inválidas.");
            return View(user);
        }
    }

        private string EncryptPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
    }
}
