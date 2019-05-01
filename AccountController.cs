using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System.Configuration;
using System.Data.SqlClient;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Data.Entity.Core.Objects;
using System.Data.Entity.Core.Metadata;
using MVCEmail.Models;
using System.Net.Mail;
using System.Net;


namespace MVCEmail.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public AccountController()
        {
        }
        
        public AccountController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _signInManager = value;
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }
        
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            string number = "";
            string constr = ConfigurationManager.ConnectionStrings["EmailDatabaseEntities"].ConnectionString;
            using (SqlConnection con = new SqlConnection(constr))
            {
                con.Open();
                string query1 = "SELECT Contact FROM RegistrationDetails WHERE  Email LIKE @Email";
                using (SqlCommand cmd = new SqlCommand(query1, con))
                {
                    SqlDataAdapter da = new SqlDataAdapter(query1, con);
                    cmd.Connection = con;
                    cmd.Parameters.AddWithValue("@Email", model.Email);
                    cmd.ExecuteNonQuery();
                    SqlDataReader reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        number = reader["contact"].ToString();
                    }
                }

            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
            var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout: false);
            
            switch (result)
            {
                case SignInStatus.Success:
                    var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), number);
                    if (UserManager.SmsService != null)
                    {
                        var message = new IdentityMessage
                        {
                            Destination = number,
                            Body = "Welcome to kruti's webpage Your security code is here: " + code
                        };
                        await UserManager.SmsService.SendAsync(message);
                    }
                    return RedirectToAction("VerifyPhoneNumber", new { ReturnUrl = returnUrl, PhoneNumber = number });
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }
        
        // GET: /Account/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), phoneNumber);
            

            // Send an SMS through the SMS provider to verify the phone number
            return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
        }

        //
        // POST: /Account/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            
            var result = await UserManager.ChangePhoneNumberAsync(User.Identity.GetUserId(), model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("Home");
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Failed to verify phone");
            return View(model);
        }

        // GET: /Account/VerifyCode
        [AllowAnonymous]
        public async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            // Require that the user has already logged in via username/password or external login
            if (!await SignInManager.HasBeenVerifiedAsync())
            {
                return View("Error");
            }
            return View(new VerifyCodeViewModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

        //
        // POST: /Account/VerifyCode
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyCode(VerifyCodeViewModel model)
        
            var vryfy = "NO";
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in IdentityConfig
            
            string constr = ConfigurationManager.ConnectionStrings["EmailDatabaseEntities"].ConnectionString;
            var result = await SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                 using (SqlConnection con = new SqlConnection(constr))
                    {
                        vryfy = "YES";
                        con.Open();
                        string query = "INSERT INTO LoginDetails(Email,Password,LoginTime,SecurityCode,Verify) VALUES (@Email, @Password, @LoginTime,@SecurityCode,@Verify)";

                        using (SqlCommand cmd1 = new SqlCommand(query))
                        {
                            cmd1.Parameters.AddWithValue("@Email", model.Email);
                            cmd1.Parameters.AddWithValue("@Password", model.Password);
                            cmd1.Parameters.AddWithValue("@SecurityCode", model.Code);
                            cmd1.Parameters.AddWithValue("@Verify", vryfy);
                            cmd1.Parameters.AddWithValue("@LoginTime", DateTime.Now);
                            cmd1.ExecuteScalar();
                        }
                        con.Close();
                    }
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View("Lockout");
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(model);
            }
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            string constr = ConfigurationManager.ConnectionStrings["EmailDatabaseEntities"].ConnectionString;
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                Session["UserId"] = user.Id;
                Session["Email"] = model.Email;

                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    using (SqlConnection con = new SqlConnection(constr))
                    {
                        string query = "INSERT INTO RegistrationDetails(FirstName,LastName,Email,Password,contact,CreateDate) VALUES (@FirstName, @LastName, @Email, @Password, @Contact, @CreateDate)";
                        //query += " SELECT SCOPE_IDENTITY()";
                        using (SqlCommand cmd = new SqlCommand(query))
                        {
                            cmd.Connection = con;
                            con.Open();
                            cmd.Parameters.AddWithValue("@FirstName", model.FirstName);
                            cmd.Parameters.AddWithValue("@LastName", model.LastName);
                            cmd.Parameters.AddWithValue("@Email", model.Email);
                            cmd.Parameters.AddWithValue("@Password", model.Password);
                            cmd.Parameters.AddWithValue("@Contact", model.Contact);
                            cmd.Parameters.AddWithValue("@CreateDate", DateTime.Now);
                           cmd.ExecuteScalar();
                            con.Close();
                        }
                    }
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
                    // Send an email with this link
                    var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                    var mymessage = new MailMessage();
                    mymessage.To.Add(new MailAddress(model.Email));  // replace with valid value 
                    mymessage.From = new MailAddress("sender@domain.com");  // replace with valid value
                    mymessage.Subject = "Verify your EmailId";
                    mymessage.Body = string.Format("Dear"+ model.FirstName + "<BR/>Thank you for your registration,please click on the below link to complete your registration:" +
                        "<a href=\"" + callbackUrl + "\">here</a>");
                    mymessage.IsBodyHtml = true;

                    using (var smtp = new SmtpClient())
                    {
                        var credential = new NetworkCredential
                        {
                            UserName = "sender@domain.com",  // replace with valid value
                            Password = "yourPassword"  // replace with valid value
                        };
                        smtp.Credentials = credential;
                        smtp.Host = "smtp.gmail.com";
                        smtp.Port = 587;
                        smtp.EnableSsl = true;
                        await smtp.SendMailAsync(mymessage);
                    }
                }
                AddErrors(result);
            }
            return View(model);
        }
        

        // GET: /Account/ConfirmEmail
        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await UserManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }
    
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            Response.Cookies.Clear();
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_userManager != null)
                {
                    _userManager.Dispose();
                    _userManager = null;
                }

                if (_signInManager != null)
                {
                    _signInManager.Dispose();
                    _signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }
}
