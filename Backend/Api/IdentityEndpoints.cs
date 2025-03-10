using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Api;

public static class IdentityEndpoints
{
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();
    public static RouteGroupBuilder MapIdentityApi(this RouteGroupBuilder group)
    {
        // default endpoints
        group.MapIdentityApi<IdentityUser>();
        // customized endpoints
        group.MapPost("/logout", async Task<NoContent>(SignInManager<IdentityUser> signInManager) =>
        {
            await signInManager.SignOutAsync();
            return TypedResults.NoContent();
        });
        group.MapPost("/register-new", async Task<Results<Ok, ValidationProblem>>
            ([FromBody] RegisterRequest registration, HttpContext context, UserManager<IdentityUser> userManager, IUserStore<IdentityUser> userStore) =>
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
            // TODO: email sender
            //await SendConfirmationEmailAsync(user, userManager, context, email);
            return TypedResults.Ok();
        });
        return group;
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
}

