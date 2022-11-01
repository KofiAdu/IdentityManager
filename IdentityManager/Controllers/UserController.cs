using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic;
using System.Security.Claims;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [Authorize(Roles = "Admin")]
        public IActionResult Index()
        {
            //get a list of users
            var userList  = _context.AppUsers.ToList();

            //get a list of roles
            var rolelist  = _context.Roles.ToList();

            //get a listof user roles
            var userRoles = _context.UserRoles.ToList();

            //iterate through users and find the roles associated wiith them
            foreach(var user in userList)
            {
                var role = userRoles.FirstOrDefault(x => x.UserId == user.Id);
                if(role == null)
                {
                    user.Role = "None";
                }
                else
                {
                    user.Role = rolelist.FirstOrDefault(x => x.Id == role.RoleId).Name;
                }
            }
            return View(userList);
        }

        [HttpGet]
        //edit a user's role
        public IActionResult Edit(string userId)
        {
            //getting user object from database
            var userObjFromDb = _context.AppUsers.FirstOrDefault(x => x.Id == userId);

            //check for null
            if(userObjFromDb == null)
            {
                //error notification
                TempData[SD.Error] = "User not found!";

                return NotFound();
            }

            //get a list of roles
            var rolelist = _context.Roles.ToList();

            //get a listof user roles
            var userRoles = _context.UserRoles.ToList();

            //checking if user has already been assigned a role
            var role = userRoles.FirstOrDefault(x => x.UserId == userObjFromDb.Id);

            if(role != null)
            {
                //populating the role id 
                userObjFromDb.RoleId = rolelist.FirstOrDefault(x => x.Id == role.RoleId).Id;
            }

            //populating the dropdown list
            userObjFromDb.RoleList = _context.Roles.Select(x => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = x.Name,
                Value = x.Id
            });
            return View(userObjFromDb);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(AppUser appUser)
        {
            if (!ModelState.IsValid)
            {
                //getting user object from database
                var userObjFromDb = _context.AppUsers.FirstOrDefault(x => x.Id == appUser.Id);

                //check for null
                if (userObjFromDb == null)
                {
                    //error notification
                    TempData[SD.Error] = "User not found!";

                    return NotFound();
                }

                //get a list of roles
                //var rolelist = _context.Roles.FirstOrDefault(x => x.Id == appUser.RoleId);

                //get user role
                var userRoles = _context.UserRoles.FirstOrDefault(x => x.UserId == userObjFromDb.Id);
                if (userRoles != null)
                {
                    //get the previous role
                    var previousRole = _context.Roles.Where(x => x.Id == userRoles.RoleId).Select(a => a.Name).FirstOrDefault();

                    //removing old role
                    await _userManager.RemoveFromRoleAsync(userObjFromDb, previousRole);
                }

                //adding the new role
                //outside the if statement to facilitate new roles even if the user has no role
                await _userManager.AddToRoleAsync(userObjFromDb, _context.Roles.FirstOrDefault(x => x.Id == appUser.RoleId).Name);

                //update name
                userObjFromDb.Name = appUser.Name;

                //save changes
                _context.SaveChanges();

                //notification
                TempData[SD.Success] = "User has been updated successfully";

                //redirect to Index action method
                return RedirectToAction(nameof(Index));
            }
            
            //populating the dropdown list even if ModelState is invalid
            appUser.RoleList = _context.Roles.Select(x => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = x.Name,
                Value = x.Id
            });
            return View(appUser);
        }


        //lock out feature
        [HttpPost]
        public IActionResult LockUnlock(string userId)
        {
            var objFromDb = _context.AppUsers.FirstOrDefault(x => x.Id == userId);
            if(objFromDb == null)
            {
                //error notification
                TempData[SD.Error] = "User Id not found";
                return NotFound();
            }

            if(objFromDb.LockoutEnd != null && objFromDb.LockoutEnd > DateTime.Now)
            {
                //lockout duration
                //action to unlock user
                objFromDb.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully";
            }
            else
            {
                //locking user
                objFromDb.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked successfully";
            }
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public IActionResult Delete(string userId)
        {
            var objFromDb = _context.AppUsers.FirstOrDefault(x => x.Id == userId);
            if (objFromDb == null)
            {
                //error notification
                TempData[SD.Error] = "User Id not found";
                return NotFound();
            }

            _context.AppUsers.Remove(objFromDb);
            _context.SaveChanges();
            TempData[SD.Success] = "User deleted";

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userId);
            
            if(user == null)
            {
                return NotFound();
            }

            //getiing claims already made available to the user
            var existingUserClaims = await _userManager.GetClaimsAsync(user);

            var userClaimsViewModel = new UserClaimsViewModel()
            {
                UserId = user.Id
            };

            foreach(Claim claim in ClaimStore.claimList)
            {
                UserClaim userClaim = new UserClaim()
                {
                    ClaimType = claim.Type
                };


                //checking box if user claim already exist
                if(existingUserClaims.Any(x => x.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }

                userClaimsViewModel.Claims.Add(userClaim);
            }

            return View(userClaimsViewModel);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel userClaimsVM)
        {
            IdentityUser user = await _userManager.FindByIdAsync(userClaimsVM.UserId);

            if (user == null)
            {
                return NotFound();
            }

            //getting claims
            var claims = await _userManager.GetClaimsAsync(user);

            //remving alreading existing claims
            var result = await _userManager.RemoveClaimsAsync(user, claims);

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Claims was not removed";
                return View(userClaimsVM);
            }

            //adding new claims
            result = await _userManager.AddClaimsAsync(user, userClaimsVM.Claims.Where(x => x.IsSelected).Select(a => new Claim(a.ClaimType, a.IsSelected.ToString())));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Couldn't Add Claims";
                return View(userClaimsVM);
            }

            TempData[SD.Success] = "Claims updated successfully";
            return RedirectToAction(nameof(Index));
        }
    }
}
