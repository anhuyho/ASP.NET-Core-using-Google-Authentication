using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GoogleAuthentication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddAuthentication(
                option =>
                {
                    option.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;//Cookies
                    option.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;//Google
                   // option.DefaultChallengeScheme = "GoogleOpenID";
                }
                )
            .AddCookie(option =>
                       {
                           option.LoginPath = "/login";
                           option.AccessDeniedPath = "/denied";
                           option.LogoutPath = "/";

                           option.Events = new CookieAuthenticationEvents
                           {
                               OnSigningIn = async context =>
                               {
                                   var identiyClaims = context.Principal.Identity as ClaimsIdentity;
                                   var huy = context.Principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier && c.Value == "huy");
                                   if (huy is not null)
                                   {
                                       var adminClaim = new Claim(ClaimTypes.Role, "Admin");

                                       identiyClaims.AddClaim(adminClaim);


                                   }
                                   var scheme = context.Properties.Items.FirstOrDefault(k => k.Key == ".AuthScheme");
                                   var claim = new Claim(scheme.Key, scheme.Value);
                                   

                                   identiyClaims.AddClaim(claim);
                               },
                               OnSignedIn = async context =>
                               {
                                   await Task.CompletedTask;
                               },
                               OnValidatePrincipal = async context =>
                               {
                                   System.Console.WriteLine("Validate PRINCIPAL");
                                   await Task.CompletedTask;
                               }
                           };
                       })
            .AddOpenIdConnect("google",option=>
            {
                option.Authority = "https://accounts.google.com";
                option.ClientId = "666506623048-vkt3s2drnk3f91h94ive7r3jo4at9vut.apps.googleusercontent.com";
                option.ClientSecret = "LkqkI5GUw1Fjwk2LFhTLAaJE";
                option.CallbackPath = "/auth";
                option.SignedOutCallbackPath = "/google-signout";
                option.SaveTokens = false;

                option.Events = new OpenIdConnectEvents()
                {
                    OnTokenValidated = async context =>
                    {
                        var claims = context.Principal.Claims;
                        if (context.Principal.Claims.Any(c=>c.Type == ClaimTypes.NameIdentifier && c.Value == "118366383695577652222"))
                        {
                            var identiyClaims = context.Principal.Identity as ClaimsIdentity;

                            var adminClaim = new Claim(ClaimTypes.Role, "Admin");

                            identiyClaims.AddClaim(adminClaim);
                        }
                    }
                };


                option.ClaimActions.MapJsonKey("urn:google:picture", "picture", "url");
                option.ClaimActions.MapJsonKey("urn:google:locale", "locale", "string");
                //option.AuthorizationEndpoint += "?prompt=consent";

            })
            //.AddGoogle(option =>
            //{
            //    option.ClientId = "666506623048-vkt3s2drnk3f91h94ive7r3jo4at9vut.apps.googleusercontent.com";
            //    option.ClientSecret = "LkqkI5GUw1Fjwk2LFhTLAaJE";
            //    option.CallbackPath = "/auth";
            //    option.AuthorizationEndpoint += "?prompt=consent";
            //})
            ;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.Use(async (context, next) =>
            {
                System.Console.WriteLine("before UseRouting !!!!");

                await next.Invoke();
            });
            app.UseRouting();
            app.Use(async (context, next) =>
            {
                System.Console.WriteLine("before authentication !!!!");

                await next.Invoke();
            });
            app.UseAuthentication();
            app.Use(async (context, next) =>
            {
                var isAuthenticated = context.User.Identity.IsAuthenticated;
                if (isAuthenticated)
                {
                    System.Console.WriteLine("done authentication !!!!");

                    var identiyClaims = context.User.Identity as ClaimsIdentity;
                    var adminClaim = new Claim(ClaimTypes.Role, "Admin");
                    identiyClaims.AddClaim(adminClaim);
                }
                
                await next.Invoke();
            });
            app.UseAuthorization();


            app.Use(async (context, next) =>
            {
            var isAuthenticated = context.User.Identity.IsAuthenticated;
                if (isAuthenticated)
                {
                    System.Console.WriteLine("done AUTHORIZATION !!!!");

                    
                }
                
                await next.Invoke();
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
