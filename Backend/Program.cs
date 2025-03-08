using Backend.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddAuthorization();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(
    options => options.UseSqlite(connectionString));
builder.Services
    .AddIdentityApiEndpoints<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi(); //add /openapi/v1.json
    app.UseSwaggerUi(options =>
    {
        options.DocumentPath = "/openapi/v1.json";
    }); // add /swagger endpoint
}

app.UseHttpsRedirection();

app.MapGet("/", () => "Hello, World!");
app.MapGet("/requires-auth", (ClaimsPrincipal user) => $"Hello, {user.Identity?.Name}!").RequireAuthorization();

app.MapGroup("/identity").MapIdentityApi<IdentityUser>();
app.MapGroup("/identity").MapPost("/logout", async (SignInManager<IdentityUser> signInManager,
    ClaimsPrincipal user) =>
{
    if (user.Identity?.Name != null)
    {
        await signInManager.SignOutAsync();
        return Results.Ok();
    }
    return Results.Unauthorized();
});

app.Run();