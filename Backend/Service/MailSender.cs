using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Backend.Service;

public class MailSender: IEmailSender
{
    private readonly ILogger _logger;
    private readonly IConfiguration _config;
    private readonly ISendGridClient _sendGridClient;
    public MailSender(ILogger<MailSender> logger, IConfiguration config, ISendGridClient sendGridClient)
    {
        _logger = logger;
        _config = config;
        _sendGridClient = sendGridClient;
    }

    public async Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        _logger.LogInformation("Send Mail");
        var fromEmail = _config.GetValue<string>("FromEmail") ?? throw new Exception("FromEmail should not be null or empty"); 
        var fromName = _config.GetValue<string>("FromName") ?? throw new Exception("FromName should not be null or empty");
        var msg = new SendGridMessage()
        {
            From = new EmailAddress(fromEmail, fromName),
            Subject = subject,
            HtmlContent = htmlMessage,
        };
        msg.AddTo(new EmailAddress(email));
        _logger.LogInformation("Call Api");
        var response = await _sendGridClient.SendEmailAsync(msg);
        // A success status code means SendGrid received the email request and will process it.
        // Errors can still occur when SendGrid tries to send the email. 
        // If email is not received, use this URL to debug: https://app.sendgrid.com/email_activity 
        if (response.IsSuccessStatusCode){
            _logger.LogInformation("Email queued successfully!"); 
        } else {
            _logger.LogError("Something went wrong!");
        }
    }
}