using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManager.Models
{
    public class AppUser : IdentityUser
    {
        [Required]
        public string Name { get; set; }

        [NotMapped]//not added to the database
        public string RoleId { get; set; }

        [NotMapped]//not added to the database
        public string Role { get; set; }
        [NotMapped]
        public IEnumerable<SelectListItem> RoleList { get; set; }
    }
}
