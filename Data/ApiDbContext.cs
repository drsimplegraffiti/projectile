
using AuthLawan.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthLawan.Data
{
    public class ApiDbContext: IdentityDbContext
    {
        
        public ApiDbContext(DbContextOptions<ApiDbContext> options) : base(options)
        {
            
        }

        public DbSet<Book> Books { get; set; }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}