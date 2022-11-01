using IdentityManager.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize(Roles = "Admin")]
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<IdentityUser> _userManager;

        public RolesController(ApplicationDbContext context, RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            var roles = _context.Roles.ToList();
            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string id)//update and insert, role ids are string
        {
            if (String.IsNullOrEmpty(id))
            {
                return View();
            }
            else
            {
                var roleFromDb = _context.Roles.FirstOrDefault(x => x.Id == id);
                return View(roleFromDb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        //adding custom authorization requirement handler
        [Authorize(Policy = "AdminAuthorization")]
        public async Task<IActionResult> Upsert(IdentityRole identityRole)//takes IdentityRole obj as parameter
        {
            //checking if role exists
            if(await _roleManager.RoleExistsAsync(identityRole.Name))
            {
                //error notification
                TempData[SD.Error] = "Role already exists";

                //redirect to main page
                return RedirectToAction(nameof(Index));
            }

            //checking role id
            if (String.IsNullOrEmpty(identityRole.Id))
            {
                //create new role
                await _roleManager.CreateAsync(new IdentityRole() { Name = identityRole.Name });
                //notification
                TempData[SD.Success] = "Role successfully created";
            }
            else
            {
                //update
                //find role by Id
                var roleObj = _context.Roles.FirstOrDefault(x => x.Id == identityRole.Id);

                //check for no role
                if(roleObj == null)
                {
                    //error notification
                    TempData[SD.Error] = "Role not found";

                    //redirect to main page
                    return RedirectToAction(nameof(Index));
                }

                //assign name
                roleObj.Name = identityRole.Name;

                //assign normalized name (Uppercase)
                roleObj.NormalizedName = identityRole.Name.ToUpper(); 

                //upadte the role
                var result = await _roleManager.UpdateAsync(roleObj);

                //notification
                TempData[SD.Success] = "Role successfully updated";
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        //adding custom authorization requirement handler
        [Authorize(Policy = "AdminAuthorization")]
        public async Task<IActionResult> Delete(string id)
        {
            var roleObj = _context.Roles.FirstOrDefault(x => x.Id == id);

            //checking if role exista
            if(roleObj == null)
            {
                TempData[SD.Error] = "Role not found";
                return RedirectToAction(nameof(Index));
            }

            var userRoleAssigned = _context.UserRoles.Where(x => x.RoleId == id).Count();
            if(userRoleAssigned > 0)
            {
                //notification
                TempData[SD.Error] = "Cannot delete role already assigned to a user";

                //redirect to home
                return RedirectToAction(nameof(Index));
            }

            //delete role
            await _roleManager.DeleteAsync(roleObj);

            //notification
            TempData[SD.Success] = "Role Deleted";

            //redirect to home
            return RedirectToAction(nameof(Index));
        }
    }
}
