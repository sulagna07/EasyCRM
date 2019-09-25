

===============================================================================================
<?xml version="1.0" encoding="utf-8"?>
<configuration>
<system.webServer>
  <rewrite>
    <rules>
      <rule name="Angular Routes" stopProcessing="true">
        <match url="^satafclient/" />
        <conditions logicalGrouping="MatchAll">
          <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
          <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
        </conditions>
        <action type="Rewrite" url="/satafclient/" />
      </rule>
    </rules>
  </rewrite>
</system.webServer>

</configuration>

==========================================================================================
[HttpPost("[action]")]
        public dynamic TestExecuter(LohaRequest lohaRequest)
        {
            HomeBaseBusinessResponse<TransactionModel> response = new HomeBaseBusinessResponse<TransactionModel>();
            BusinessData<TransactionModel> bsData = new BusinessData<TransactionModel>();

            TransactionModel tran = new TransactionModel();
            tran.Id = "T2345";
            tran.Name = "SBI";
            
            bsData.Data = tran;
            bsData.BusinessErrorMsg = string.Empty;
            bsData.IsValid = true;

            response.Exception = null;
            response.Success = true;
            response.BusinessData = bsData;
            return response;
        }
===================================================================================
[HttpPost("[action]")]
        public async Task<dynamic> TestExecutor([FromBody]LohaRequest request)
        {
            try
            {
                UserData userData = new UserData();
                userData.Name = "Jhon";
                userData.Role = "Admin";
                var msg = await _client.PostAsync("commonapi/TestExecuter", request);//commonexecuter
                var model=JsonConvert.DeserializeObject<HomeBaseBusinessResponse<dynamic>>(msg);
                HomeBaseResponse<dynamic> response = new HomeBaseResponse<dynamic>();
                if (model.Success)
                {
                    response.UserData = userData;
                    response.CacheData = "Test";
                    response.BusinessData = model.BusinessData;
                    response.Success = model.Success;
                }
                else
                {
                    response.Success = false;
                    response.Exception = model.Exception;
                }
                return response;
            }
            catch (Exception ex)
            {
                LohaResponse<string> resp = new LohaResponse<string>();
                resp.Success = false;
                resp.Message = ex.Message;
                resp.Data = string.Empty;
                return JsonConvert.SerializeObject(resp, new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() });
            }

        }
        
=========================================================================================================================
public class BaseResponse
    {
        public bool Success { get; set; }
        public LogError Exception { get; set; }
    }

    public class HomeBaseBusinessResponse<T>: BaseResponse
    {
        public BusinessData<T> BusinessData { get; set; }
    }

    public class HomeBaseResponse<T> : BaseResponse
    {
        public BusinessData<T> BusinessData { get; set; }
        public string CacheData { get; set; }
        public UserData UserData { get; set; }
    }

    public class BusinessData<T>
    {
        public bool IsValid { get; set; }
        public T Data { get; set; }
        public string BusinessErrorMsg { get; set; }
    }

    public class UserData
    {
        public string Name { get; set; }
        public string Role { get; set; }
    }

    public class LogError
    {
        public string Message { get; set; }
        public string ErrorCode { get; set; }
        public ErrorSeverity Severity { get; set; }
    }

    public enum ErrorSeverity{
        High,Medium,Low
    }

    public class TransactionModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }
}
============================================================================================
using System.Security.Claims;
using System.Web.Http;
[HttpPost]
[AllowAnonymous]
public IHttpActionResult UserLogin(UserLoginModel userParam)
{
    var user = _userService.Authenticate(userParam.UserName, userParam.Password);

    if (user == null)
        return NotFound();//BadRequest(new { message = "Username or password is incorrect" });

    return Ok(user);
}
[HttpPost]
[Authorize(Roles = Role.Admin)]
public IHttpActionResult CommonExecutor(CrmRequest request)
{
    var identity = (ClaimsIdentity)User.Identity;
    var userName= identity.FindFirst(ClaimTypes.Name).Value;
    var roleName = identity.FindFirst(ClaimTypes.Role).Value;
    return Ok("Done");
}
==========================================================================
  using AngularApiJwt.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace AngularApiJwt.Services
{
    public class UserService
    {
        private static string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
        // users hardcoded for simplicity, store in a db with hashed passwords in production applications
        private List<User> _users = new List<User>
        {
            new User { Id = 1, FirstName = "Admin", LastName = "User", Username = "admin", Password = "admin", Role = Role.Admin },
            new User { Id = 2, FirstName = "Normal", LastName = "User", Username = "user", Password = "user", Role = Role.User }
        };

        public User Authenticate(string username, string password)
        {
            var user = _users.SingleOrDefault(x => x.Username == username && x.Password == password);

            // return null if user not found
            if (user == null)
                return null;

            // authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString()),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Audience = "abc.com",
                Issuer="abc.com",
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.WriteToken(token);

            // remove password before returning
            user.Password = null;

            return user;
        }

        public void ValidateToken(string token, out string userName, out string role)
        {
            userName = string.Empty;
            role = string.Empty;
            string username = null;
            ClaimsPrincipal principal = GetPrincipal(token);
            if(principal != null)
            {
                ClaimsIdentity identity = null;
                try
                {
                    identity = (ClaimsIdentity)principal.Identity;
                    Claim usernameClaim = identity.FindFirst(ClaimTypes.Name);
                    Claim roleClaim = identity.FindFirst(ClaimTypes.Role);
                    username = usernameClaim.Value;
                    role = roleClaim.Value;
                }
                catch (NullReferenceException)
                {
                    return;
                }
            }           
        }
        public ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
                if (jwtToken == null) return null;
                var key = Encoding.ASCII.GetBytes(Secret);
                TokenValidationParameters parameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidAudience = "abc.com",
                    ValidIssuer = "abc.com",
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
                return principal;
            }
            catch(Exception ex)
            {
                return null;
            }
        }
    }
}
==============================================================================
  using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Owin;
using System.Text;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(AngularApiJwt.Startup))]

namespace AngularApiJwt
{
    public class Startup
    {
        private static string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
        public void Configuration(IAppBuilder app)
        {
            app.UseCors(CorsOptions.AllowAll);
            app.UseJwtBearerAuthentication(new JwtBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "abc.com",
                    ValidAudience = "abc.com",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret))
                }

            });
        }
    }
}
=======================================================
  Microsoft.Owin.Host.SystemWeb
  public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services


            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
=======================================================================================
  using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.OAuth;
using Owin;
using JwtAuthTest.Models;
using JwtAuthTest.Providers;

namespace JwtAuthTest
{
    public partial class Startup
    {
        // Enable the application to use OAuthAuthorization. You can then secure your Web APIs
        static Startup()
        {
            PublicClientId = "web";

            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                TokenEndpointPath = new PathString("/Token"),
                AuthorizeEndpointPath = new PathString("/Account/Authorize"),
                Provider = new ApplicationOAuthProvider(PublicClientId),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                AllowInsecureHttp = true
            };
        }

        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        public static string PublicClientId { get; private set; }

        // For more information on configuring authentication, please visit https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(20),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
        }
    }
}
Startup.Auth
=============================================================
  using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(JwtAuthTest.Startup))]

namespace JwtAuthTest
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
================================================
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json.Serialization;

namespace JwtAuthTest
{
    public static class WebApiConfig
    {
        public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services
            // Configure Web API to use only bearer token authentication.
            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // Use camel case for JSON data.
            config.Formatters.JsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
===============================================================================
https://www.blinkingcaret.com/2018/05/30/refresh-tokens-in-asp-net-core-web-api/
https://www.c-sharpcorner.com/article/handle-refresh-token-using-asp-net-core-2-0-and-json-web-token/
https://angular-academy.com/angular-jwt/
https://fullstackmark.com/post/19/jwt-authentication-flow-with-refresh-tokens-in-aspnet-core-web-api
https://houseofcat.io/tutorials/aspnet/addjwtauthentication
