namespace IdentityManager.ViewModels
{
    public class TwoFactorAuthenticationViewModel
    {
        //used to log  in
        public string Code { get; set; }

        //used to register
        public string Token { get; set; }

        //adding qrcode
        //public string QRCodeUri { get; set; }   
    }
}
