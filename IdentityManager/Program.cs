using IdentityManager.Data;
using IdentityManager.Helpers;
using IdentityManager.Interfaces;
using IdentityManager.PersonalizedAuthorization;
using IdentityManager.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

//adding services (email services)
builder.Services.AddTransient<ISendGridEmail, SendGridEmail>();

//forgot the note lol
builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration.GetSection("SendGrid"));
//adding sign-in options
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.Lockout.MaxFailedAccessAttempts = 5;
});

//setting default  paths
builder.Services.ConfigureApplicationCookie(options =>
{
    //access denied path
    options.AccessDeniedPath = new Microsoft.AspNetCore.Http.PathString("/Home/AccessDenied");
});

//configuring facebook login authentication 
builder.Services.AddAuthentication().AddFacebook(options =>
{
    //add your facebook app id and app secret
    options.AppId = "";
    options.AppSecret = "";
});

//configure google login
builder.Services.AddAuthentication().AddGoogle(options =>
{
    //add your google clientid and aclient secret
    options.ClientId = "";
    options.ClientSecret = "";
});


//configuring policy based authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    options.AddPolicy("Admin_CreateAccess", policy => policy.RequireRole("Admin").RequireClaim("create", "True"));
    options.AddPolicy("Admin_Create_Edit_DeleteAccess(", policy => policy.RequireRole("Admin").RequireClaim("create", "True").RequireClaim("edit","True").RequireClaim("delete","True"));

    //adding custom handler policy
    options.AddPolicy("AdminAuthorization", policy => policy.Requirements.Add(new AdminAuthorization()));
});

builder.Services.AddControllersWithViews();



var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//add authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
