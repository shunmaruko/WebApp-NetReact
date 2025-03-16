using SendGrid;
using SendGrid.Helpers.Mail;

namespace Backend.Service;
public static class MailSender
{
    public static async Task SendMail(ISendGridClient sendGridClient, string fromMail, string fromName, string toMail, string toName, string subject, string body)
    {
        Console.WriteLine("Send Mail");
        var msg = new SendGridMessage()
        {
            From = new EmailAddress(fromMail, fromName),
            Subject = subject,
            PlainTextContent = body
        };
        msg.AddTo(new EmailAddress(toMail, toName));
        Console.WriteLine("Call Api");
        var response = await sendGridClient.SendEmailAsync(msg);
        Console.WriteLine("response");
        // A success status code means SendGrid received the email request and will process it.
        // Errors can still occur when SendGrid tries to send the email. 
        // If email is not received, use this URL to debug: https://app.sendgrid.com/email_activity 
        Console.WriteLine(response.IsSuccessStatusCode ? "Email queued successfully!" : "Something went wrong!");

    }
}