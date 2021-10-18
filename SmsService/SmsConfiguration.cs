using System;

namespace SmsService
{
    public class SmsConfiguration
    {
        public string AccountSID { get; set; }
        public string AuthToken { get; set; }
        public string From { get; set; }
    }
}
