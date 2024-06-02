using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SimpleNewsSystem.Data;
using SimpleNewsSystem.Models;

namespace SimpleNewsSystem.Controllers;

public class HomeController : Controller
{
    private readonly ApplicationDbContext _context;

    public HomeController(ApplicationDbContext context)
    {
        _context = context;
    }

    public IActionResult Index()
    {
        var newsItems = _context.NewsItems.ToList();
        return View(newsItems);
    }

    // Outras actions do HomeController...
}

