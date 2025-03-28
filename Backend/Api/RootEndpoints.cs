using System.Security.Claims;

namespace Backend.Api;

public static class RootEndpoints
{
    public static RouteGroupBuilder MapRootApi(this RouteGroupBuilder group)
    {
        group.MapGet("/", () => "Hello, World!");
        group.MapGet("/requires-auth", (ClaimsPrincipal user) => $"Hello, {user.Identity?.Name}!").RequireAuthorization();
        return group;
    }
}