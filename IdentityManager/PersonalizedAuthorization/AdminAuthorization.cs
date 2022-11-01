using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.PersonalizedAuthorization
{

    //creating a custom authorization requirement handler
    //custom authorization handler implements AuthorizationHandler
    //AuthorizationHAndler expects a generic Requirement, you can add your custom requirement even if it's created in another class, 
    //for this, i am checking the requirement within this same class so i use that as the paramenter for the AuthorizationHandler
    //this class should also implement IAuthorizationRequirement
    //no need to register in Program.cs file since it's already implemented here
    public class AdminAuthorization : AuthorizationHandler<AdminAuthorization>, IAuthorizationRequirement
    {
        //implementing the abstract classes
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminAuthorization requirement)
        {
            if (context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);

                //go to the next
                return Task.CompletedTask;
            }
            return Task.CompletedTask;  
        }
    }
}
