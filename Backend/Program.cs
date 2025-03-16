using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using SendGrid;
using SendGrid.Helpers.Mail;
using Backend.Data;
using Backend.Api;
using Backend.Service;
using SendGrid.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddUserSecrets<Program>(); // required to use secrets

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

builder.Services.Configure<IdentityOptions>(options =>
{
    // Default Lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    // Default Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;
    // Default SignIn settings.
    options.SignIn.RequireConfirmedEmail = false;
    options.SignIn.RequireConfirmedPhoneNumber = false;
    // Default User settings.
    options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true; // defaults to false
});
// add send grid to di container
builder.Services.AddSendGrid(options => 
{
    options.ApiKey = builder.Configuration.GetValue<string>("SendGridApiKey");
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    // add /openapi/v1.json
    app.MapOpenApi(); 
    // add /swagger endpoint
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/openapi/v1.json", "v1");
    });
    // save seed data
    app.InitDb();
}

app.UseHttpsRedirection();

app.MapGroup("/").MapRootApi();
app.MapGroup("/identity").MapIdentityApi();

//app.Run();
// send mail
var fromEmail = builder.Configuration.GetValue<string>("FromEmail") ?? throw new Exception("FromEmail should not be null or empty"); 
var fromName = builder.Configuration.GetValue<string>("FromName") ?? throw new Exception("FromName should not be null or empty");
var apiKey = builder.Configuration.GetValue<string>("SendGridApiKey") ?? throw new Exception("SendGridApiKey should not be null or empty"); 
var toEmail = builder.Configuration.GetValue<string>("ToEmail") ?? throw new Exception("ToEmail should not be null or empty"); 
var subject = "Sample Subject";
var body = "Sample Body";
var client = app.Services.GetRequiredService<ISendGridClient>();
await MailSender.SendMail(client, fromEmail, fromName, toEmail, toEmail, subject, body);

