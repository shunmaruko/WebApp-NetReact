using SendGrid;
using SendGrid.Helpers.Mail;

namespace Backend.Service;
public class SendMailArg
{
    public required List<string> ToMailList { get; set; }
    public required string Subject { get; set; }
    public required string Body { get; set; }
}
    
public static class MailSender
{
    private class MailSenderLogger(ILogger<MailSenderLogger> logger)
    {
        
        public void LogInformation(string message)
        {
            logger.LogInformation(message);
        }
        public void LogError(string message)
        {
            logger.LogError(message);
        }
    }

    public static async Task<Response> SendMail(HttpContext context, SendMailArg sendMailArg)
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<MailSenderLogger>>();
        logger.LogInformation("Send Mail");
        var config = context.RequestServices.GetRequiredService<IConfiguration>();
        var fromEmail = config.GetValue<string>("FromEmail") ?? throw new Exception("FromEmail should not be null or empty"); 
        var fromName = config.GetValue<string>("FromName") ?? throw new Exception("FromName should not be null or empty");
        var msg = new SendGridMessage()
        {
            From = new EmailAddress(fromEmail, fromName),
            Subject = sendMailArg.Subject,
            PlainTextContent = sendMailArg.Body
        };
        foreach (string toEmail in sendMailArg.ToMailList)
        {
            msg.AddTo(new EmailAddress(toEmail));
        }
        logger.LogInformation("Call Api");
        var sendGridClient = context.RequestServices.GetRequiredService<ISendGridClient>();
        var response = await sendGridClient.SendEmailAsync(msg);
        // A success status code means SendGrid received the email request and will process it.
        // Errors can still occur when SendGrid tries to send the email. 
        // If email is not received, use this URL to debug: https://app.sendgrid.com/email_activity 
        if (response.IsSuccessStatusCode){
            logger.LogInformation("Email queued successfully!"); 
        } else {
            logger.LogError("Something went wrong!");
        }
        return response;
    }
}