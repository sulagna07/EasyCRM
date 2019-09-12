routes.MapRoute(
                    name: "areas",
                    template: "{area:exists}/{controller=Home}/{action=Index}/{id?}"
                );
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}"
                );
===================
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace HBAuthTest.Controllers
{
    [Route("external/[controller]")]
    public class OktaLoginController : Controller
    {
        /*[HttpPost("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            var userClaims = HttpContext.User.Claims;
            return Content("Test");
        }*/

        /*[HttpGet("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            Resource res = new User();
            var userClaims = HttpContext.User.Claims;
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                //return Content("Test2");
                return Challenge(OktaDefaults.MvcAuthenticationScheme);
            }
            return Content("Test3");
            
        }*/

        [HttpGet("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            //Resource res = new User();
            var userClaims = HttpContext.User.Claims;
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                var dt=new OktaTokenService().GetToken();
                return Content("Test3");
            }
            return Content("Test4");
        }
    }
    public class OktaTokenService //: ITokenService
    {
        private OktaToken token = new OktaToken();
        //private readonly IOptions<OktaSettings> oktaSettings;

        /*public OktaTokenService(IOptions<OktaSettings> oktaSettings)
        {
            this.oktaSettings = oktaSettings;
        }*/

        public async Task<string> GetToken()
        {
            if (!this.token.IsValidAndNotExpiring)
            {
                this.token = await this.GetNewAccessToken();
            }
            return token.AccessToken;
        }

        private async Task<OktaToken> GetNewAccessToken()
        {
            var token = new OktaToken();
            var client = new HttpClient();
            var client_id = "0oaneni0j4pKmU3hG0h7";//this.oktaSettings.Value.ClientId;
            var client_secret = "h7EkLQ8WbYJkI83l31o0sV0sBO73A1UItSXevlDR";//this.oktaSettings.Value.ClientSecret;
            var clientCreds = System.Text.Encoding.UTF8.GetBytes($"{client_id}:{client_secret}");
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Basic", System.Convert.ToBase64String(clientCreds));

            var postMessage = new Dictionary<string, string>();
            postMessage.Add("grant_type", "client_credentials");
            postMessage.Add("scope", "access_token");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://dev-198806.oktapreview.com/oauth2/default/v1/token")//  this.oktaSettings.Value.TokenUrl
            {
                Content = new FormUrlEncodedContent(postMessage)
            };

            var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                token = JsonConvert.DeserializeObject<OktaToken>(json);
                token.ExpiresAt = DateTime.UtcNow.AddSeconds(this.token.ExpiresIn);
            }
            else
            {
                throw new ApplicationException("Unable to retrieve access token from Okta");
            }

            return token;
        }

    }

    public class OktaToken
    {
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        [JsonProperty(PropertyName = "expires_in")]
        public int ExpiresIn { get; set; }

        public DateTime ExpiresAt { get; set; }

        public string Scope { get; set; }

        [JsonProperty(PropertyName = "token_type")]
        public string TokenType { get; set; }

        public bool IsValidAndNotExpiring
        {
            get
            {
                return !String.IsNullOrEmpty(this.AccessToken) &&
          this.ExpiresAt > DateTime.UtcNow.AddSeconds(30);
            }
        }
    }
}
====================================================================
         services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OktaDefaults.MvcAuthenticationScheme;
            })
.AddCookie()
.AddOktaMvc(new OktaMvcOptions
{
    OktaDomain = "https://dev-198806.oktapreview.com",
    ClientId = "0oaneni0j4pKmU3hG0h7",
    ClientSecret = "h7EkLQ8WbYJkI83l31o0sV0sBO73A1UItSXevlDR",
    Scope = new List<string> { "openid", "profile", "email" }
});

app.UseAuthentication();
=============================================================================
upgraded users:
https://developer.okta.com/pricing/
https://www.okta.com/free-trial/
https://www.okta.com/integrate/signup/

https://developer.okta.com/docs/guides/implement-auth-code/use-flow/
https://github.com/okta/samples-aspnetcore/blob/master/okta-hosted-login/okta-aspnetcore-mvc-example/Startup.cs
https://developer.okta.com/blog/2017/06/29/oidc-user-auth-aspnet-core
https://developer.okta.com/okta-sdk-dotnet/latest/api/Okta.Sdk.User.html
https://github.com/okta/samples-aspnetcore
https://developer.okta.com/blog/2018/02/01/secure-aspnetcore-webapi-token-auth