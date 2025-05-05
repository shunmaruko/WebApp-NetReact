using Backend.Service;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Backend.Api;

public static class EmailEndpoints
{
    public static RouteGroupBuilder MapEmailApi(this RouteGroupBuilder group)
    {
        group.MapPost("/send", async Task<Results<Ok, BadRequest>> (MailSender mailSender, string email, string subject, string htmlMessage) => 
        {   
            try
            {
                await mailSender.SendEmailAsync(email, subject, htmlMessage);
                return TypedResults.Ok(); 
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return TypedResults.BadRequest();
            }
        });
        return group;
    }
}