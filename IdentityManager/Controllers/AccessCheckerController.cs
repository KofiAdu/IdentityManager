using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //available to everyone, even users not ogged in
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        //only logged in users
        [Authorize]
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        //only users withe the role "user" has access
        //role based authorization
        [Authorize(Roles = "User")]
        public IActionResult UserAccess()
        {
            return View();
        }

        //Accesible by users and admin
        //role based authorization
        [Authorize (Roles = "User,Admin")]//acts as an OR condition
        public IActionResult UserOrAdminAccess()
        {
            return View();
        }

        //accessible only by admin
        //role based authorization
        [Authorize(Roles = "Admin")]
        //or we could use policy based authorization
        //policy authorization also allows for AND condition
        //[Authorize(Policy = "Admin")]
        public IActionResult AdminAccess()
        {
            return View();
        }

        //accesible to admin users with claim of true
        //policy based authorization
        [Authorize(Policy = "Admin_CreateAccess")]
        public IActionResult Admin_CreateAccess() 
        { 
            return View(); 
        }

        //accessible by Admin user with create, edit and delete
        //policy based authorization
        [Authorize(Policy = "Admin_Create_Edit_DeleteAccess")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }

    }
}
