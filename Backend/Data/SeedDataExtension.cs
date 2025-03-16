
using Backend.Data;
using Microsoft.AspNetCore.Identity;

namespace Backend.Data;

public static class SeedDataExtension
{
    public static  void InitDb(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>()
                ?? throw new InvalidOperationException("Failed to retrieve store context");
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>()
                ?? throw new InvalidOperationException("Failed to retrieve user manager");
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>()
                ?? throw new InvalidOperationException("Failed to retrieve user manager");
            SeedRole(context, roleManager);
            SeedUser(context, userManager);
        }

    }
    private static async void SeedRole(ApplicationDbContext context, RoleManager<IdentityRole> roleManager)
    {
        context.Database.EnsureCreated();
        var roles = new List<string> { "Admin", "General"};
        foreach (var roleName in roles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new IdentityRole(roleName));
            }
        }
        context.SaveChanges();
    }

    private static async void SeedUser(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        context.Database.EnsureCreated();
        // if no user in db
        if (!userManager.Users.Any()) 
        {
            var admin = new IdentityUser
            {
                UserName = "admin@test.com",
                Email = "admin@test.com",
            };
            await userManager.CreateAsync(admin, "Pa$$w0rd");
            await userManager.AddToRolesAsync(admin, ["Admin", "General"]);
        }
        context.SaveChanges();
    }
}