using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Backend.Data;
public class ApplicationDbContext : IdentityDbContext<IdentityUser, IdentityRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
        //Database.EnsureCreated();
    }
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<IdentityRole>()
            .HasData(
                new IdentityRole {Id="3efb8943-ff63-4328-877b-8c1a5f9bd07a", Name="General", NormalizedName="GENERAL"},
                new IdentityRole {Id="5b5397e9-5247-4eb2-9516-ed34bce0d4a9", Name="Admin", NormalizedName="ADMIN"}
            );
    }
}