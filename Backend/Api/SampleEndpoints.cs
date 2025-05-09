using System.Security.Claims;

namespace Backend.Api;

public static class SampleEndpoints
{
    public static RouteGroupBuilder MapSampleApi(this RouteGroupBuilder group)
    {
        group.MapGet("/", () => "Hello, World!");
        group.MapGet("/protected-me", (ClaimsPrincipal user) => $"Hello, {user.Identity?.Name}!").RequireAuthorization();
        return group;
    }
}