using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Backend.Api;

public static class IdentityEndpoints
{
    //pls see https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Core/src/IdentityApiEndpointRouteBuilderExtensions.cs
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();
    
    public static RouteGroupBuilder MapIdentityApi(this RouteGroupBuilder routeGroup)
    {
        // We'll figure out a unique endpoint name based on the final route pattern during endpoint generation.
        string? confirmEmailEndpointName = null;
        // default endpoints
        //group.MapIdentityApi<IdentityUser>();
        routeGroup.MapPost("/login", async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>>
            ([FromBody] LoginRequest login, [FromQuery] bool? useCookies, [FromServices] IServiceProvider sp) =>
        {
            var signInManager = sp.GetRequiredService<SignInManager<IdentityUser>>();
            var useCookieScheme = useCookies == true;
            var isPersistent = useCookies == true;
            signInManager.AuthenticationScheme = useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;
            var user = await signInManager.UserManager.FindByEmailAsync(login.Email);
            if (user == null || !await signInManager.UserManager.IsEmailConfirmedAsync(user))
            {
                return TypedResults.Problem("Email is not confirmed.", statusCode: StatusCodes.Status401Unauthorized);
            }
            var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: false);

            if (!result.Succeeded)
            {
                return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
            }
            // The signInManager already produced the needed response in the form of a cookie or bearer token.
            return TypedResults.Empty;
        });
        // customized endpoints
        routeGroup.MapPost("/logout", async Task<NoContent>(SignInManager<IdentityUser> signInManager) =>
        {
            await signInManager.SignOutAsync();
            return TypedResults.NoContent();
        });
        routeGroup.MapPost("/register", async Task<Results<Ok, ValidationProblem>>
            ([FromBody] RegisterRequest registration, HttpContext context, [FromServices] UserManager<IdentityUser> userManager, [FromServices] IUserStore<IdentityUser> userStore) =>
        {

            if (!userManager.SupportsUserEmail)
            {
                throw new NotSupportedException($"register-new requires a user store with email support.");
            }

            var emailStore = (IUserEmailStore<IdentityUser>)userStore;
            var email = registration.Email;
            if (string.IsNullOrEmpty(email) || !_emailAddressAttribute.IsValid(email))
            {
                return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email)));
            }

            var user = new IdentityUser();
            await userStore.SetUserNameAsync(user, email, CancellationToken.None);
            await emailStore.SetEmailAsync(user, email, CancellationToken.None);
            var result = await userManager.CreateAsync(user, registration.Password);
            if (!result.Succeeded)
            {
                return CreateValidationProblem(result);
            }
            var result2 = await userManager.AddToRoleAsync(user, "General");
            if (!result2.Succeeded)
            {
                return CreateValidationProblem(result);
            }
            if (userManager.Options.SignIn.RequireConfirmedEmail){
                // if succeeeded, redirect to server host
                var request = context.Request;
                var serverHost = $"{request.Scheme}://{request.Host}";
                await SendConfirmationEmailAsync(user, userManager, context, email, serverHost, false);
            }
            else 
            {
                throw new NotSupportedException($"register-new requires account confirmation");
            }
            return TypedResults.Ok();
        });
        routeGroup.MapGet("/confirmEmail", async Task<IResult>
            ([FromQuery] string userId, [FromQuery] string code, [FromQuery] string? changedEmail, [FromQuery] string? returnUri, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            if (await userManager.FindByIdAsync(userId) is not { } user)
            {
                // We could respond with a 404 instead of a 401 like Identity UI, but that feels like unnecessary information.
                return TypedResults.Unauthorized();
            }

            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                return TypedResults.Unauthorized();
            }

            IdentityResult result;

            if (string.IsNullOrEmpty(changedEmail))
            {
                result = await userManager.ConfirmEmailAsync(user, code);
            }
            else
            {
                // As with Identity UI, email and user name are one and the same. So when we update the email,
                // we need to update the user name.
                result = await userManager.ChangeEmailAsync(user, changedEmail, code);

                if (result.Succeeded)
                {
                    result = await userManager.SetUserNameAsync(user, changedEmail);
                }
            }

            if (!result.Succeeded)
            {
                return TypedResults.Unauthorized();
            }
            if (!string.IsNullOrEmpty(returnUri) && Uri.TryCreate(returnUri, UriKind.Absolute, out var validReturnUri))
            {
                // only extract host name (not contain port)
                var serverHost = context.Request.Host.Host.ToString();
                var allowedHosts = new[] { "yourfrontend.com", "app.yourfrontend.com", serverHost};
                if (allowedHosts.Contains(validReturnUri.Host))
                {
                    return TypedResults.Redirect(validReturnUri.AbsoluteUri); // or LocalRedirect if same origin
                }
            }
            return TypedResults.Text("Thank you for confirming your email.");
        })
        .Add(endpointBuilder =>
        {
            var finalPattern = ((RouteEndpointBuilder)endpointBuilder).RoutePattern.RawText;
            confirmEmailEndpointName = $"{nameof(MapIdentityApi)}-{finalPattern}";
            endpointBuilder.Metadata.Add(new EndpointNameMetadata(confirmEmailEndpointName));
        });

        routeGroup.MapPost("/resendConfirmationEmail", async Task<Ok>
            ([FromBody] ResendConfirmationEmailRequest resendRequest, HttpContext context, [FromServices] IServiceProvider sp) =>
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            if (await userManager.FindByEmailAsync(resendRequest.Email) is not { } user)
            { // in case email not found in db
                return TypedResults.Ok();
            }
            var is_already_confirmed = await userManager.IsEmailConfirmedAsync(user);
            if (is_already_confirmed)
            { // in case user alrady confirmed
                return TypedResults.Ok();
            }
            await SendConfirmationEmailAsync(user, userManager, context, resendRequest.Email);
            return TypedResults.Ok();
        });
        async Task SendConfirmationEmailAsync(IdentityUser user, UserManager<IdentityUser> userManager, HttpContext context, string email, string? returnUri = null, bool isChange = false)
        {
            var mailSender = context.RequestServices.GetRequiredService<IEmailSender>();
            var linkGenerator = context.RequestServices.GetRequiredService<LinkGenerator>();
            var code = isChange
                    ? await userManager.GenerateChangeEmailTokenAsync(user, email)
                    : await userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var userId = await userManager.GetUserIdAsync(user);
            var routeValues = new RouteValueDictionary()
            {
                ["userId"] = userId,
                ["code"] = code,
            }; 
            if (! string.IsNullOrEmpty(returnUri))
            {
                routeValues.Add("returnUri", returnUri);
            }
            if (isChange)
            {
                // This is validated by the /confirmEmail endpoint on change.
                routeValues.Add("changedEmail", email);
            }
            if (confirmEmailEndpointName is null)
            {
                throw new NotSupportedException("No email confirmation endpoint was registered.");
            }
            var confirmEmailUrl = linkGenerator.GetUriByName(context, confirmEmailEndpointName, routeValues)
                ?? throw new NotSupportedException($"Could not find endpoint named '{confirmEmailEndpointName}'.");
            await mailSender.SendEmailAsync(
                email, 
                "Account Confirmation Mail", 
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(confirmEmailUrl)}'>clicking here</a>."
            );
        }
        routeGroup.MapPost("/forgotPassword", async Task<Results<Ok, ValidationProblem>>
            ([FromBody] ForgotPasswordRequest resetRequest, [FromServices] IServiceProvider sp) =>
        {
            var mailSender = sp.GetRequiredService<IEmailSender>();
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            var user = await userManager.FindByEmailAsync(resetRequest.Email);

            if (user is not null && await userManager.IsEmailConfirmedAsync(user))
            {
                var code = await userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var resetPasswordUrlBase = ""; // TODO: After making frontend, return correct url
                var resetUrl = $"{resetPasswordUrlBase}?Email={user.Email}&ResetCode={HtmlEncoder.Default.Encode(code)}";
                var email = user.Email ?? throw new NotSupportedException("Users must have an email.");
                await mailSender.SendEmailAsync(
                    user.Email, 
                    "Password Reset Mail", 
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(resetUrl)}'>clicking here</a>."
                );
            }
            // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
            // returned a 400 for an invalid code given a valid user email.
            return TypedResults.Ok();
        });

        routeGroup.MapPost("/resetPassword", async Task<Results<Ok, ValidationProblem>>
            ([FromBody] ResetPasswordRequest resetRequest, [FromServices] IServiceProvider sp) =>
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();

            var user = await userManager.FindByEmailAsync(resetRequest.Email);

            if (user is null || !await userManager.IsEmailConfirmedAsync(user))
            {
                // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
                // returned a 400 for an invalid code given a valid user email.
                return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken()));
            }

            IdentityResult result;
            try
            {
                var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
                result = await userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
            }
            catch (FormatException)
            {
                result = IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken());
            }

            if (!result.Succeeded)
            {
                return CreateValidationProblem(result);
            }

            return TypedResults.Ok();
        });

        var accountGroup = routeGroup.MapGroup("/manage").RequireAuthorization();
        accountGroup.MapGet("/info", async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, [FromServices] IServiceProvider sp) =>
        {
            var userManager = sp.GetRequiredService<UserManager<IdentityUser>>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }

            return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
        });
        return routeGroup;
    }
    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }
    private static async Task<InfoResponse> CreateInfoResponseAsync(IdentityUser user, UserManager<IdentityUser> userManager)
    {
        return new()
        {
            Email = await userManager.GetEmailAsync(user) ?? throw new NotSupportedException("Users must have an email."),
            Roles = await userManager.GetRolesAsync(user),
        };
    }
}


/// <summary>
/// The request type for the "/login" endpoint 
/// </summary>
public sealed class LoginRequest
{
    /// <summary>
    /// The user's email address which acts as a user name.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// The user's password.
    /// </summary>
    public required string Password { get; init; }
}


public sealed class InfoResponse
{
    /// <summary>
    /// The email address associated with the authenticated user.
    /// </summary>
    public required string Email { get; init; }
    /// <summary>
    /// Roles of user.
    /// </summary>
    public required IList<string> Roles { get; set; }
}