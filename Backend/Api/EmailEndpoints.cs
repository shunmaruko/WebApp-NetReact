using Backend.Service;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Backend.Api;

public static class EmailEndpoints
{
    public static RouteGroupBuilder MapEmailApi(this RouteGroupBuilder group)
    {
        group.MapPost("/send", async Task<Results<Ok, BadRequest>> (HttpContext context, SendMailArg sendMailArg) => 
        {   
            
            var response = await MailSender.SendMail(context, sendMailArg);
            if (response.IsSuccessStatusCode){
                return TypedResults.Ok();
            } else{
                return TypedResults.BadRequest();
            }
        });
        return group;
    }
}