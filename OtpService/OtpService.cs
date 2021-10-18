using System;
using System.Collections.Generic;
using System.Text;

namespace OtpService
{
    public class OtpService : IOtpService
    {
         public string generateOtp()
        {
            var secret = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secret);
            HttpContext.Session.SetString("OtpKey", base32Secret);
            var totp = new Totp(secret);
            var code = totp.ComputeTotp();
            return code;
        }
    }
}
