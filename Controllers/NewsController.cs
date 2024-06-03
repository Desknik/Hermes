using Microsoft.AspNetCore.Mvc;
using SimpleNewsSystem.Data;
using SimpleNewsSystem.Filters;
using SimpleNewsSystem.Models;
using System.Linq;

namespace SimpleNewsSystem.Controllers
{
    public class NewsController : Controller
    {
        private readonly ApplicationDbContext _context;

        public NewsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: News
        public IActionResult Index()
        {
            var newsItems = _context.NewsItems.ToList();
            return View(newsItems);
        }

        // GET: News/Create
        [TypeFilter(typeof(AdminAuthorizationFilter))]
        public IActionResult Create()
        {
            return View();
        }

        // POST: News/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        [TypeFilter(typeof(AdminAuthorizationFilter))]
        public IActionResult Create(NewsItem newsItem)
        {
            if (ModelState.IsValid)
            {
                _context.NewsItems.Add(newsItem);
                _context.SaveChanges();
                return RedirectToAction(nameof(Index));
            }
            return View(newsItem);
        }

        // GET: News/Edit/5
        [TypeFilter(typeof(AdminAuthorizationFilter))]
        public IActionResult Edit(int id)
        {
            var newsItem = _context.NewsItems.Find(id);
            if (newsItem == null)
            {
                return NotFound();
            }
            return View(newsItem);
        }

        // POST: News/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [TypeFilter(typeof(AdminAuthorizationFilter))]
        public IActionResult Edit(int id, NewsItem newsItem)
        {
            if (id != newsItem.id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                _context.Update(newsItem);
                _context.SaveChanges();
                return RedirectToAction(nameof(Index));
            }
            return View(newsItem);
        }

        // GET: News/Delete/5
        [TypeFilter(typeof(AdminAuthorizationFilter))]
        public IActionResult Delete(int id)
        {
            var newsItem = _context.NewsItems.Find(id);
            if (newsItem == null)
            {
                return NotFound();
            }
            return View(newsItem);
        }

        [HttpPost, ActionName("DeleteConfirmed")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var newsItem = await _context.NewsItems.FindAsync(id);
            if (newsItem != null)
            {
                _context.NewsItems.Remove(newsItem);
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }
        
        
    }
}
