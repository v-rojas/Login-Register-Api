using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using EmailService;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NetCoreApi.Authentication;
using NetCoreApi.Models;
using Newtonsoft.Json;
using OtpNet;
using SmsService;

namespace NetCoreApi.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly IEmailSender emailSender;
        private readonly ISmsSender smsSender;

        public AuthenticationController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, 
            IConfiguration configuration, IEmailSender emailSender, ISmsSender smsSender)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            this.emailSender = emailSender;
            this.smsSender = smsSender;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
                var token = new JwtSecurityToken(
                    issuer: configuration["JWT:ValidIssuer"],
                    audience: configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            var userExists = await userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });
            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
            if (!await roleManager.RoleExistsAsync(model.Role))
                await roleManager.CreateAsync(new IdentityRole(model.Role));
            if (await roleManager.RoleExistsAsync(model.Role))
                await userManager.AddToRoleAsync(user, model.Role);
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("generate-otp")]
        public async Task<IActionResult> GenerateOtp(string reference)
        {
            if (reference.Contains("@"))
            {
                var userExists = await userManager.FindByEmailAsync(reference);
                if (userExists == null)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response 
                    { Status = "Error", Message = "No account associated with this email!", Data = "" });
                string code = generateOtp();
                // Send Email
                var files = Request.Form.Files.Any() ? Request.Form.Files : new FormFileCollection();
                var message = new Message(new string[] { reference }, "Net Core Authentication Api", $"This is the Otp number {code}", files);
                await emailSender.SendEmail(message);
            } else
            {
                string code = generateOtp();
                // Send Sms
                smsSender.SendSms($"+{reference}", code);
            }                      
            return Ok(new Response { Status = "Success", Message = "Otp generated successfully!" });
        }

        [HttpPost]
        [Route("validate-otp")]
        public IActionResult ValidateOtp(string Otp)
        {
            string base32Secret = HttpContext.Session.GetString("OtpKey");
            var secret = Base32Encoding.ToBytes(base32Secret);
            var totp = new Totp(secret);               
            bool status = totp.VerifyTotp(Otp, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);
            var json = new
            {
                Status = status
            };
            string jsonData = JsonConvert.SerializeObject(json);
            return Ok(new Response { Status = status ? "Success" : "Error", Message = status ? "Otp is valid" : "Otp is invalid", Data = jsonData });
        }

        [HttpPost]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(string email, string password)
        {
            var userExists = await userManager.FindByEmailAsync(email);
            if (userExists == null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                { Status = "Error", Message = "No account associated with this user!", Data = "" });
            var token = await userManager.GeneratePasswordResetTokenAsync(userExists);
            var resetPassResult = await userManager.ResetPasswordAsync(userExists, token, password);
            if (!resetPassResult.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response
                { Status = "Error", Message = "It has occured an error while changing the password!", Data = "" });
            }
            return Ok(new Response { Status = "Success", Message = "Your password has been changed!", Data = "" });
        }

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
