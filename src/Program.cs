using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Company.WebApplication1.Data;
using Microsoft.AspNetCore.Builder;
using Company.WebApplication1.Services.Mail;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Company.WebApplication1.Services.Profile;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddControllersWithViews();


builder.Services.Configure<CookiePolicyOptions>(options =>
{
    // This lambda determines whether user consent for non-essential cookies is needed for a given request.
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = (Microsoft.AspNetCore.Http.SameSiteMode)SameSiteMode.None;
});

builder.Services.Configure<CookieTempDataProviderOptions>(options =>
{
    options.Cookie.IsEssential = true;
});

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(config =>
{
    config.User.RequireUniqueEmail = true;    // óíèêàëüíûé email
    config.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -._@+";
    config.SignIn.RequireConfirmedEmail = false;
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

if (builder.Configuration["Authentication:Facebook:IsEnabled"] == "true")
{
    builder.Services
        .AddAuthentication()
        .AddFacebook(facebookOptions => {
            facebookOptions.AppId = builder.Configuration["Authentication:Facebook:AppId"];
            facebookOptions.AppSecret = builder.Configuration["Authentication:Facebook:AppSecret"];
        });
}

if (builder.Configuration["Authentication:Google:IsEnabled"] == "true")
{
    builder.Services
        .AddAuthentication()
        .AddGoogle(googleOptions => {
            googleOptions.ClientId = builder.Configuration["Authentication:Google:ClientId"];
            googleOptions.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        });
}

builder.Services.AddMvc()
    .AddRazorPagesOptions(options =>
    {
        options.Conventions.AuthorizeFolder("/");

        options.Conventions.AllowAnonymousToPage("/Error");
        options.Conventions.AllowAnonymousToPage("/Account/AccessDenied");
        options.Conventions.AllowAnonymousToPage("/Account/ConfirmEmail");
        options.Conventions.AllowAnonymousToPage("/Account/ExternalLogin");
        options.Conventions.AllowAnonymousToPage("/Account/ForgotPassword");
        options.Conventions.AllowAnonymousToPage("/Account/ForgotPasswordConfirmation");
        options.Conventions.AllowAnonymousToPage("/Account/Lockout");
        options.Conventions.AllowAnonymousToPage("/Account/Login");
        options.Conventions.AllowAnonymousToPage("/Account/LoginWith2fa");
        options.Conventions.AllowAnonymousToPage("/Account/LoginWithRecoveryCode");
        options.Conventions.AllowAnonymousToPage("/Account/Register");
        options.Conventions.AllowAnonymousToPage("/Account/ResetPassword");
        options.Conventions.AllowAnonymousToPage("/Account/ResetPasswordConfirmation");
        options.Conventions.AllowAnonymousToPage("/Account/SignedOut");
    });

builder.Services.Configure<MailManagerOptions>(builder.Configuration.GetSection("Email"));

if (builder.Configuration["Email:EmailProvider"] == "SendGrid")
{
    builder.Services.Configure<SendGridAuthOptions>(builder.Configuration.GetSection("Email:SendGrid"));
    builder.Services.AddSingleton<IMailManager, SendGridMailManager>();
}
else
{
    builder.Services.AddSingleton<IMailManager, EmptyMailManager>();
}

builder.Services.AddScoped<ProfileManager>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCookiePolicy();

app.UseRouting();

app.UseAuthorization();
app.UseAuthentication();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();