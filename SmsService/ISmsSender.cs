using System;
using System.Collections.Generic;
using System.Text;

namespace SmsService
{
    public interface ISmsSender
    {
        string SendSms(string phone, string code);
    }
}
