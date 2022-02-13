using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using GoogleAuthentication.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GoogleAuthentication.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize(Roles ="Admin")]
        public IActionResult AdminSecured()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secured()
        {
            return View();
        }

        [HttpGet]
        [Route("login")]
        public IActionResult Login(string returnURL)
        {
            ViewData["returnURL"] = returnURL;
            return View();
        }
        [HttpGet("login/{provider}")]
        [AllowAnonymous]
        public IActionResult LoginExternal([FromRoute] string provider, [FromQuery]string returnURL)
        {
            if (User != null && User.Identities.Any(i=>i.IsAuthenticated))
            {
                RedirectToAction("", "Home");
            }
            returnURL = string.IsNullOrEmpty(returnURL) ? "/" : returnURL;
            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = returnURL
            };
            return new ChallengeResult(provider, authenticationProperties);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(string returnURL, string username, string password)
        {
            if ((username == "huy" && password == "rookies") || (username == "ti" && password == "director"))
            {
                var claims = new List<Claim>
                {
                    new Claim("username", username),
                    new Claim(ClaimTypes.NameIdentifier, username),
                    new Claim(ClaimTypes.Name, username)
                };
                //claims.Add(new Claim(ClaimTypes.Role, "Admin"));
                var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                
                var claimPrincipal = new ClaimsPrincipal(claimIdentity);
                var items = new Dictionary<string, string>();
                items.Add(".AuthScheme", CookieAuthenticationDefaults.AuthenticationScheme);
                var properties = new AuthenticationProperties(items);
                await HttpContext.SignInAsync(claimPrincipal, properties);

                if (string.IsNullOrEmpty(returnURL))
                {
                    returnURL = "/";
                }
                return Redirect(returnURL);
            }
            TempData["Error"] = "Username or Password is not correct";
            return Redirect("login");
        }
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var scheme = User.Claims.FirstOrDefault(c => c.Type == ".AuthScheme")?.Value;
            if (scheme == "google")
            {
                await HttpContext.SignOutAsync();

                return Redirect(@"https://www.google.com/accounts/Logout?continue=https://appengine.google.com/_ad/logout?continue=https://localhost:5001");
            }
            else
            {
                await HttpContext.SignOutAsync();
                return Redirect("/");
                //return new SignOutResult(new [] { scheme });
            }
            //
            
            //return Redirect(@"https://www.google.com/accounts/Logout?continue=https://www.google.com/url?sa=d&q=https://localhost:5001   ");
        }

        [Authorize]
        [Route("denied")]
        public IActionResult Denied()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
