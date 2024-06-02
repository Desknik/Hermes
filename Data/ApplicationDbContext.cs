using Microsoft.EntityFrameworkCore;
using SimpleNewsSystem.Models;

namespace SimpleNewsSystem.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<NewsItem> NewsItems { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("users"); // Especifique o nome exato da tabela
            });

            modelBuilder.Entity<NewsItem>(entity =>
            {
                entity.ToTable("news_items"); // Especifique o nome exato da tabela
            });
        }
    }
}
