namespace IdentityManager.ViewModels
{
    public class VerifyAuthenticatorViewModel
    {
        public string Code { get; set; }
        public string ReturnUrl { get; set; }
        public bool RememberMe { get; set; }
    }
}
