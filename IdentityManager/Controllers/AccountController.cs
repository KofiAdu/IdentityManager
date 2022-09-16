using IdentityManager.Interfaces;
using IdentityManager.Models;
using IdentityManager.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        /// <summary>
        /// create UserManager and SignInManager to facilitate creating a new user and signing them in
        /// </summary>

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISendGridEmail _sendGridEmail;
        private readonly UrlEncoder _urlEncoder;
        //private readonly RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, ISendGridEmail sendGridEmail,
            UrlEncoder urlEncoder)
        {

            _userManager = userManager;
            _signInManager = signInManager;
            _sendGridEmail = sendGridEmail;
            _urlEncoder = urlEncoder;
            //_roleManager = roleManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            RegisterViewModel registerViewModel = new();
            return View(registerViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel register, string? returnUrl = null)
        {
            //specifying a default return url to prevent ArguementException: Value Caannot be null (Parameter "localUrl")
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                //fill user details
                var user = new AppUser { UserName = register.Name, Email = register.Email, Name = register.Name };

                //create user
                //CreateAsync takes the appuser instance and the password to create a new user
                var result = await _userManager.CreateAsync(user, register.Password);

                //check success to sign in
                if (result.Succeeded)
                {
                    //verifying email before signing user in
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var callbackurl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: HttpContext.Request.Scheme);

                    //send email to the user with the callback url
                    await _sendGridEmail.SendEmailAsync(register.Email, "Email Confirmation", "Please follow this link to confirm your email" + "<a href=\"" + callbackurl + "\"> link</a>");

                    //sign the user in
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    // return RedirectToAction("Index","Home");//added home to specify that controller's index
                    return LocalRedirect(returnUrl);
                }

                //if sign in is unsuccessful, add errors from result
                AddErrors(result);
            }

            return View(register);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if(userId == null || code == null)
            {
                return View("Error");
            }

            //find user by id
            var user = await _userManager.FindByIdAsync(userId);
            if(user == null)
            {
                return View("Error");
            }

            //allow user to confirm their email
            var result = await _userManager.ConfirmEmailAsync(user, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl= null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel login, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            returnUrl ??= Url.Content("~/");
            if (ModelState.IsValid)
            {
                //sigining in the user
                //if you sigin in with PasswordSignInAsync then you need to login with username 
                var result = await _signInManager.PasswordSignInAsync(login.Name, login.Password, login.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    //if it requires TFA
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { ReturnUrl = returnUrl, RememberMe = login.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    return View("LockOut");
                }
                else
                {
                    //show error messsage if login was not succesful
                    ModelState.AddModelError(string.Empty, "Invalid login attempt");
                    return View(login);
                }
            }

            return View(login);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index","Home");
        }

        //forgot password 
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPassword)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(forgotPassword.Email);
                if(user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirm");
                }

                //generating token to allow password change
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);

                //callback url used to reset password
                //Url.Action takes action name and controller name a
                //
                var callbackurl = Url.Action("ResetPassword", "Account", new {userId = user.Id, code= code}, protocol:HttpContext.Request.Scheme);

                //send email to the user with the callback url
                await _sendGridEmail.SendEmailAsync(forgotPassword.Email, "Reset Confirmation", "Please follow this link to reset your password" + "<a href=\"" + callbackurl + "\"> link</a>");

                return RedirectToAction("ForgotPasswordConfirm");
            }
            return View(forgotPassword);
        }

        //forgot password confirmation
        [HttpGet]
        public IActionResult ForgotPasswordConfirm()
        {
            return View();
        }

        //reset password 
        [HttpGet]
        public IActionResult ResetPassword(string? code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetPassword)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(resetPassword.Email);
                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConfirm");
                }

                var result = await _userManager.ResetPasswordAsync(user, resetPassword.Code, resetPassword.Password);
                if (result.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConfirm");
                }
               
                //add errors if the reset fails
                AddErrors(result);
            }
            return View();
        }



        //reset password confirmation
        [HttpGet]
        public IActionResult ResetPasswordConfirm()
        {
            return View();
        }


        //external login
        //post request
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            //request a redirect to the external login
            var redirectUrl = Url.Action("ExternalLoginCallback","Account", new {ReturnUrl = returnUrl});
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            //challenge requires the external login provider to verify the identity of the user
            //takes parameters *properties and the provider
            return Challenge(properties, provider);
        }

        //external login callback
        //get
        //for an existing user
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback( string? returnUrl = null, string? remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                //show error messsage from login provider(eg facebook or google) if login was not succesful
                ModelState.AddModelError(string.Empty, $"External Provider Error: {remoteError}");
                return View(nameof(Login));
            }

            //getting external login info from external login provider(eg. your login details from faceboook or  google
            var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();

            //if there is no login info, ie if user has no google or facebook account
            if(externalLoginInfo == null)
            {
                //redirect to login page
                return RedirectToAction(nameof(Login));
            }

            //if the info is available
            //Sign user in with external login provider
            var result = await _signInManager.ExternalLoginSignInAsync(externalLoginInfo.LoginProvider, externalLoginInfo.ProviderKey, isPersistent:false);
            if (result.Succeeded)
            {
                //upadte authentication tokens
                await _signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);

                //do a local redirect back to the return url
                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                //if it requires TFA
                return RedirectToAction(nameof(VerifyAuthenticatorCode), new { ReturnUrl = returnUrl});
            }
            else
            {
                //if the user has no account from the external login provider, user is allowed to create one
                //set viewdata to the returnUrl
                //set another view data to the provider display name
                ViewData["ReturnUrl"] = returnUrl;
                ViewData["ProviderDisplayName"] = externalLoginInfo.ProviderDisplayName;

                //retrieve email from external provider
                var externalLoginEmail = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Email);
                var externalLoginName = externalLoginInfo.Principal.FindFirstValue(ClaimTypes.Name);

                //return to the login in view that allows user to enter their external login email
                //view and viewmodel will be the parameters of "return View("View", new ViewModel{x = x})
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { Email=externalLoginEmail, Name = externalLoginName});
            }
        }


        //for a new user
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel externalLogin, string? returnurl = null)
        {
            //specifying a default return url to prevent ArguementException: Value Caannot be null (Parameter "localUrl")
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                //get login details from external login provider
                var externalLoginInfo = await _signInManager.GetExternalLoginInfoAsync();
                //if there is no login info, ie if user has no google or facebook account
                if (externalLoginInfo == null)
                {
                    //display error page
                    return View("Error");
                }

                //create an AppUser instance to get access to both email  and name variables
                var user = new AppUser { UserName = externalLogin.Email, Email = externalLogin.Email, Name = externalLogin.Name };

                //create a new user
                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    //add login
                    //paramters user, externalLoginInfo
                    result = await _userManager.AddLoginAsync(user, externalLoginInfo);
                    if (result.Succeeded)
                    {
                        //sign user in
                        await _signInManager.SignInAsync(user, isPersistent: false);

                        //after signing in, update external token with exteernalLoginInfo
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(externalLoginInfo);

                        //do a local redirect to the return url
                        return LocalRedirect(returnurl);
                    }
                }
                //add errors if the result faileed
                AddErrors(result);
            }
            //return returnurl if model state is not valid
            ViewData["ReturnUrl"] = returnurl;
            return View(externalLogin);
        }

        //qrcode.js file already added to the js folder
        //now we need a method that allows the MFA fucntion
        //this method needs a model with properties for tokens and qrcode
        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            //AuthenticatorUriFormat for QR code
            //Also qrcode.js file already added to the project
           // string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

            //get the logged in user by passing the global user oobject
            var user = await _userManager.GetUserAsync(User);

            //reset existing authenticator keys
            await _userManager.ResetAuthenticatorKeyAsync(user);

            //generate a new token/authenticator key
            var token = await _userManager.GetAuthenticatorKeyAsync(user);

            //formating authenticator format
            //takes the string to be formatted as the first parameter
            //the project name and user email is encoded and parsed in to be formmatted
            //also takes the token which needs no encoding
           //string AuthenticatorUri = string.Format(AuthenticatorUriFormat, _urlEncoder.Encode("IdentityManager"), _urlEncoder.Encode(user.Email), token);

            //create  a new model and assign token to the token variable
            var model = new TwoFactorAuthenticationViewModel {Token = token };

            //return to the View and pass the model 
            return View(model);
        }

        //inputing the code generated by the authenticator for validation
        [HttpPost]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel twoFactor)
        {
            if (ModelState.IsValid)
            {
                //get the logged in user by passing the global user oobject
                var user = await _userManager.GetUserAsync(User);

                //check if it's succeded
                var success = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, twoFactor.Code);
                if (success)
                {
                    //enabling two factor aauthentication
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Two Factor Authentication not validated");
                    return View(twoFactor);
                }
            }

            return RedirectToAction(nameof(AuthenticatorConfirmation));
        }

        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            //checking if user is logged in
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user == null)
            {
                return View("Error");
            }
            ViewData["ReturnUrl"] = returnUrl;
            return View(new VerifyAuthenticatorViewModel { RememberMe = rememberMe, ReturnUrl = returnUrl});
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel verifyAuthenticator)
        {
            //checking if ModelState is in valid
            if (!ModelState.IsValid)
            {
                return View(verifyAuthenticator);
            }

            //setting rememberClient to true means TFA is not required as long as cookies arent expired
            //setting rememberClient to false means the user always needs to go through TFA to log in
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(verifyAuthenticator.Code, verifyAuthenticator.RememberMe, rememberClient: false);
            if (result.Succeeded)
            {
                return LocalRedirect(verifyAuthenticator.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Error");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Wrong Code. Try Again");
                return View(verifyAuthenticator);
            }
        }

        //Disabling two factor authentication
        [HttpGet]
        public async Task<IActionResult> DisableAuthenticator()
        {
           
            //get the logged in user by passing the global user oobject
            var user = await _userManager.GetUserAsync(User);

            //reset existing authenticator keys
            await _userManager.ResetAuthenticatorKeyAsync(user);

            //set TFA to false
            await _userManager.SetTwoFactorEnabledAsync(user, false);

            //redirect to the Index of the Home controller
            return RedirectToAction(nameof(Index), "Home");
        }

        //add a helper method to save errors
        public void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
