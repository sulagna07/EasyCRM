using CrmValueObjects;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Primitives;
using SGAuthFilter.SGServices;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SGAuthFilter.HBFilter
{
    internal class HBAuthorize : AuthorizeFilter, IAntiforgeryPolicy
    {
        private readonly IAntiforgery _antiforgery;
        private readonly IAuthService _authService;

        /// <summary>
        /// Initializes a new HBAuthorize Filter instance.
        /// </summary>
        public HBAuthorize(int max, IAuthorizationPolicyProvider provider, IAntiforgery antiforgery, IAuthService authService) : base(provider, new[] { new HBAuthorizeData(HBConstants.HBPolicy) })
        {
            _antiforgery = antiforgery;
            _authService = authService;
        }
        public override async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            try
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }
                // Allow Anonymous skips all authorization
                if (HasAllowAnonymous(context))
                {
                    return;
                }
                if (context.HttpContext.Items.TryGetValue("Token-Expired", out _) && !context.HttpContext.User.Identity.IsAuthenticated && TokenExists(context, out string token))
                {
                    var userPrinclipal = _authService.GetPrincipalFromToken(token);
                    context.HttpContext.User = userPrinclipal;
                    //Get the current claims principal
                    ClaimsIdentity identity = (ClaimsIdentity)userPrinclipal.Identity;
                    var userName = identity.FindFirst(ClaimTypes.Name).Value;
                    var userModel = identity.FindFirst(ClaimTypes.UserData).Value;

                    if (await IsAntiForgeryValid(context) && !string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(userModel))
                    {
                        context.HttpContext.Request.Cookies.TryGetValue("Refresh-Token", out string oldRefToken);
                        //call db
                        var newToken = _authService.CreateTokenDyn(userModel, userName);
                        var newRefToken = _authService.CreateRefreshToken();
                        context.HttpContext.Response.Headers.Add("Auth-Token", newToken);
                        context.HttpContext.Response.Cookies.Delete("Refresh-Token");
                        context.HttpContext.Response.Cookies.Append("Refresh-Token", newRefToken, new CookieOptions
                        {
                            HttpOnly = true,
                            SameSite = SameSiteMode.Strict,
                            Secure = true
                        });
                        context.HttpContext.User = _authService.GetPrincipalFromToken(newToken);
                        var tokens = _antiforgery.GetAndStoreTokens(context.HttpContext);
                        context.HttpContext.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new CookieOptions
                        {
                            HttpOnly = false,
                            SameSite = SameSiteMode.Strict,
                            Secure = true
                        });
                    }
                    else
                    {
                        context.Result = new BadRequestResult();
                    }
                }
                else if (context.HttpContext.User.Identity.IsAuthenticated)
                {
                    await base.OnAuthorizationAsync(context);
                    if (await IsAntiForgeryValid(context))
                    {

                    }
                    else
                    {
                        context.Result = new BadRequestResult();
                    }
                }
                else
                {
                    context.Result = new UnauthorizedResult();
                }
            }
            catch (Exception ex)
            {
                context.Result = new UnauthorizedObjectResult(ex.Message);
            }
        }

        private async Task<bool> IsAntiForgeryValid(AuthorizationFilterContext context)
        {
            bool isValid = true;
            if (!context.IsEffectivePolicy<IAntiforgeryPolicy>(this))
            {
                isValid = false;
            }
            try
            {
                await _antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException)
            {
                isValid = false;
            }

            return isValid;
        }

        private bool HasAllowAnonymous(AuthorizationFilterContext filterContext)
        {
            var controllerActionDescriptor = filterContext.ActionDescriptor as ControllerActionDescriptor;
            if (controllerActionDescriptor.ControllerTypeInfo.GetCustomAttributes(typeof(AllowAnonymousAttribute), inherit: true).Any() ||
                controllerActionDescriptor.MethodInfo.GetCustomAttributes(typeof(AllowAnonymousAttribute), inherit: true).Any())
            {
                return true;
            }
            return false;
        }
        private bool TokenExists(AuthorizationFilterContext context, out string token)
        {
            var tokenFound = false;
            token = null;

            if (context.HttpContext.Request.Headers.TryGetValue("Authorization", out StringValues authHeaders) && authHeaders.Any())
            {
                var bearerToken = authHeaders.ElementAt(0);
                token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
                tokenFound = true;
            }

            return tokenFound;
        }
    }

    public class HBAuthorizeAttribute : TypeFilterAttribute
    {
        public int MaxRequestPerSecond { get; set; }
        public HBAuthorizeAttribute() : base(typeof(HBAuthorize)) { }
    }
}

==================================================
using CrmValueObjects;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.Tasks;

namespace SGAuthFilter.HBFilter
{
    public static class HBAuthorization
    {
        public static IServiceCollection AddHBAuthorization(this IServiceCollection serviceCollection, IConfiguration configuration)
        {
            string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
            serviceCollection
            .AddAuthorization(options =>
            {
                options.AddHbPolicy();
            })
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = HBConstants.HBScheme;
                options.DefaultChallengeScheme = HBConstants.HBScheme;
            })
            //.AddAuthentication(Constants.AzureAdScheme)
            .AddJwtBearer(HBConstants.HBScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "abc.com",
                    ValidAudience = "abc.com",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                    ClockSkew = TimeSpan.Zero
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.HttpContext.Items.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            return serviceCollection;
        }

        public static AuthorizationOptions AddHbPolicy(this AuthorizationOptions options)
        {
            var policy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(HBConstants.HBScheme)
                .RequireAuthenticatedUser()
                .Build();

            options.AddPolicy(HBConstants.HBPolicy, policy);
            return options;
        }
    }
}
==========================================================================
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Threading.Tasks;
using CrmValueObjects;

namespace SGAuthFilter.HBFilter
{
    internal class OktaAuthorize: AuthorizeFilter
    {
        public OktaAuthorize(IAuthorizationPolicyProvider provider) : base(provider, new[] { new HBAuthorizeData(HBConstants.OktaPolicy) })
        {

        }

        public override async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            await base.OnAuthorizationAsync(context);
            if (!context.HttpContext.User.Identity.IsAuthenticated)
            {
                var tokenExist = context.HttpContext.Request.Cookies.TryGetValue("Refresh-Token", out string RefToken);//check token expiry
                if (tokenExist && !string.IsNullOrEmpty(RefToken))
                {
                    context.Result = new RedirectResult("/home", true);
                }
            }
        }
    }

    public class OktaAuthorizeAttribute : TypeFilterAttribute
    {
        public OktaAuthorizeAttribute() : base(typeof(OktaAuthorize)) { }
    }
}
=============================================================================
using CrmValueObjects;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SGAuthFilter.HBFilter
{
    public static class OktaAuthorization
    {
        public static IServiceCollection AddOktaAuthorization(this IServiceCollection serviceCollection, IConfiguration configuration)
        {
            serviceCollection
            .AddAuthorization(options =>
            {
                options.AddOktaPolicy();
            })
            .AddAuthentication(options =>
            {
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultScheme = HBConstants.OktaScheme;
            }).AddCookie()
             .AddOpenIdConnect(HBConstants.OktaScheme, options =>
             {

                 options.Authority = configuration["Okta:Domain"] + "/oauth2/default";
                 options.RequireHttpsMetadata = false; //true
                 options.ClientId = configuration["Okta:ClientId"];
                 options.ClientSecret = configuration["Okta:ClientSecret"];
                 options.CallbackPath = new PathString("/authorization-code/callback");
                 options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                 options.GetClaimsFromUserInfoEndpoint = true;
                 options.Scope.Add("openid");
                 options.Scope.Add("profile");
                 options.Scope.Add("email");
                 options.SaveTokens = true;
                 options.TokenValidationParameters = new TokenValidationParameters
                 {
                     NameClaimType = "name",
                     RoleClaimType = "groups",
                     ValidateIssuer = true
                 };
             });

            return serviceCollection;
        }

        public static AuthorizationOptions AddOktaPolicy(this AuthorizationOptions options)
        {
            var policy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(HBConstants.OktaScheme)
                .RequireAuthenticatedUser()
                .Build();

            options.AddPolicy(HBConstants.OktaPolicy, policy);
            return options;
        }
    }
}
=====================================================================
namespace CrmValueObjects
{
    public static class HBConstants
    {
        public const string OktaScheme = "HBOkta";
        public const string OktaPolicy = "HBOktaPolicy";

        public const string HBScheme = "HBJwt";
        public const string HBPolicy = "HBJwtPolicy";
        //public const string HBBearer = "HBJwtBearer";
    }
}
==================================================================
using Microsoft.AspNetCore.Authorization;

namespace CrmValueObjects
{
    public class HBAuthorizeData : IAuthorizeData
    {
        public HBAuthorizeData() { }
        public HBAuthorizeData(string policy)
        {
            this.Policy = policy;
        }
        public string Policy { get; set; }
        public string Roles { get; set; }
        public string AuthenticationSchemes { get; set; }
    }
}
====================================================================
public void ConfigureServices(IServiceCollection services)
        {
			services.AddHBAuthorization(Configuration).AddOktaAuthorization(Configuration);           
        }
app.UseAuthentication();
app.UseAuthorization();

===================================================================
[HBAuthorize(MaxRequestPerSecond = 10)]
[AllowAnonymous]
===================================================================
using CrmValueObjects;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SGAuthFilter.SGServices
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _config;
        public AuthService(IConfiguration config)
        {
            _config = config;
        }
        public string CreateTokenDyn(dynamic userModel, string userName)
        {
            try
            {
                // authentication successful so generate jwt token
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_config["AuthConfig:SecretKey"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim("sub", userName),
                    new Claim(ClaimTypes.UserData, userModel),
                    new Claim(ClaimTypes.Name, userName)
                    }, JwtBearerDefaults.AuthenticationScheme, "name", "role"),
                    NotBefore = DateTime.UtcNow,
                    Audience = _config["AuthConfig:Audiance"],
                    Issuer = _config["AuthConfig:Issuer"],
                    Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["AuthConfig:TokenExpire"])),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public string CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        public ClaimsPrincipal GetPrincipalFromToken(string token)
        {

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
            if (jwtToken == null) throw new SecurityTokenException();

            var key = Encoding.UTF8.GetBytes(_config["AuthConfig:SecretKey"]);
            TokenValidationParameters parameters = new TokenValidationParameters()
            {
                RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _config["AuthConfig:Audiance"],
                ValidIssuer = _config["AuthConfig:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            SecurityToken securityToken;
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
            return principal;
        }
        public UserClaimModel GetUserDataFromToken(string token)
        {

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
            if (jwtToken == null) throw new SecurityTokenException();

            var key = Encoding.UTF8.GetBytes(_config["AuthConfig:SecretKey"]);
            TokenValidationParameters parameters = new TokenValidationParameters()
            {
                RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _config["AuthConfig:Audiance"],
                ValidIssuer = _config["AuthConfig:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            SecurityToken securityToken;
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
            ClaimsIdentity identity = (ClaimsIdentity)principal.Identity;
            return JsonSerializer.Deserialize<UserClaimModel>(identity.FindFirst(ClaimTypes.UserData).Value);
        }

        public string GetUserStringFromToken(string token)
        {

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
            if (jwtToken == null) throw new SecurityTokenException();

            var key = Encoding.ASCII.GetBytes(_config["AuthConfig:SecretKey"]);
            TokenValidationParameters parameters = new TokenValidationParameters()
            {
                RequireExpirationTime = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _config["AuthConfig:Audiance"],
                ValidIssuer = _config["AuthConfig:Issuer"],
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            SecurityToken securityToken;
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
            ClaimsIdentity identity = (ClaimsIdentity)principal.Identity;
            return identity.FindFirst(ClaimTypes.UserData).Value;
            //return JsonSerializer.Deserialize<UserClaimModel>();
        }
        
    }
}
==================================================================
[HttpPost("[Action]")]
        [AllowAnonymous]
        [ServiceFilter(typeof(XSRFCookieFilter))]
        //[ServiceFilter(typeof(SGBrandFilter))]
        public async Task<IActionResult> UserLogin(MyRtmLoginRequest<dynamic> rtmRequest)
        {

            //var cn = HttpContext;
            //rtmRequest.IsChacheRequired = _cacheHelper.CachePopulationRequired();
            var data = await _apiClient.PostAsync<MyRtmResponse<BusinessData<dynamic>>, MyRtmLoginRequest<dynamic>>("Common/GetLoginData", rtmRequest);//MyRtmResponse<dynamic>
            if (data.Success)
            {
                var clm = CommonService.DeserializeString<UserClaimModel>(data.BusinessData.Data.ToString()) as UserClaimModel;

                var authToken = _authService.CreateTokenDyn(data.BusinessData.Data.ToString(),clm.UserName);//CommonService.DeserializeString<UserClaimModel>(data.Data)
                var refreshToken = _authService.CreateRefreshToken();
                rtmRequest.Data = new RefreshTokenModel { AuthToken = authToken, RefreshToken = refreshToken, UserId = clm.UserId, ExpiredAt = DateTime.UtcNow.AddDays(1).ToString() };
                rtmRequest.Operation = "StoreRefresh";
                rtmRequest.UserData = null;
                var rdata = await _apiClient.PostAsync<MyRtmResponse<BusinessData<dynamic>>, MyRtmLoginRequest<dynamic>>("Common/GetLoginData", rtmRequest);
                Response.Headers.Add("Auth-Token", authToken);

                Response.Cookies.Append("Refresh-Token", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Strict,
                    Secure = true
                });
                HttpContext.User = _authService.GetPrincipalFromToken(authToken);
                return Ok(data);
            }
            return NotFound(data);
        }
=========================================================================
	var builder = new ConfigurationBuilder()
              .SetBasePath(env.ContentRootPath)
              .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
              //.AddJsonFile($"Config/{env.EnvironmentName}.json", optional: false, reloadOnChange: true)
              .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: false, reloadOnChange: true)
              .AddEnvironmentVariables();
            configuration = builder.Build();
            Configuration = configuration;
==============================================================================
	<EnvironmentName>Qa</EnvironmentName>
========================================
IIS": {
      "commandName": "IIS",
      "launchBrowser": true,
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Devweb"
      }
    }
