using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace SmsService
{
    public class SmsSender : ISmsSender
    {
        private readonly SmsConfiguration _smsConfig;

        public SmsSender(SmsConfiguration smsConfig)
        {
            _smsConfig = smsConfig;
        }

        public string SendSms(string phone, string code)
        {
            TwilioClient.Init(_smsConfig.AccountSID, _smsConfig.AuthToken);
            var message = MessageResource.Create(
                    to: phone,
                    from: _smsConfig.From,
                    body: $"This is the Otp number {code}"
                );
            return message.Sid;
        }
    }
}
