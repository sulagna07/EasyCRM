using CrmValueObjects;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.Tasks;

namespace SGAuthFilter.SGFilter
{
    public static class AzureAdExtensions
    {
        public static IServiceCollection AddAzureAdAuthorization(this IServiceCollection serviceCollection, IConfiguration configuration)
        {
            string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
            serviceCollection
            .AddAuthorization(options =>
            {
                options.AddAzureAdPolicy();
            })
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = Constants.AzureAdScheme;
                options.DefaultChallengeScheme = Constants.AzureAdScheme;
            })
            .AddJwtBearer(Constants.AzureAdScheme, options =>
            {
                //options.Authority = String.Format(configuration["Authentication:Authority"], configuration["Authentication:Tenant"]);
                //options.Audience = configuration["Authentication:ClientId"];
                // Configuration for your custom
                // JWT tokens here
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

        public static AuthorizationOptions AddAzureAdPolicy(this AuthorizationOptions options)
        {
            var policy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(Constants.AzureAdScheme)
                .RequireAuthenticatedUser()
                .Build();

            options.AddPolicy(Constants.AzureAdPolicy, policy);
            return options;
        }
    }
}
========================================================================
namespace CrmValueObjects
{
    public static class Constants
    {
        public const string MyDbScheme = "MyDb";
        public const string MyDbPolicy = "MyDb";

        public const string AzureAdScheme = "AzureAd";
        public const string AzureAdPolicy = "AzureAdPolicy";
        public const string AzureAdBearer = "AzureAdBearer";
    }
}
========================================================================
using CrmValueObjects;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Primitives;
using SGAuthFilter.SGServices;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SGAuthFilter.SGFilter
{
    public class AzureAdAuthFilterAttribute : TypeFilterAttribute
    {
        public AzureAdAuthFilterAttribute() : base(typeof(SGAuthorizeFilter)) { }
    }
    public class SGAuthorizeFilter : AuthorizeFilter, IAntiforgeryPolicy//IFilterFactory IAsyncAuthorizationFilter
    {
        private readonly IAntiforgery _antiforgery;
        private readonly IAuthService _authService;

        /// <summary>
        /// Initializes a new <see cref="SGAuthorizeFilter"/> instance.
        /// </summary>
        public SGAuthorizeFilter(IAuthorizationPolicyProvider provider, IAntiforgery antiforgery, IAuthService authService) : base(provider, new[] { new AuthorizeData(Constants.AzureAdPolicy) })
        {
            _antiforgery = antiforgery;
            _authService = authService;
        }

        //bool IFilterFactory.IsReusable => true;

        public override async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            try
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }
                // Allow Anonymous skips all authorization  __AuthorizationMiddlewareWithEndpointInvoked
                if (HasAllowAnonymous(context.Filters))
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
                        context.HttpContext.User= _authService.GetPrincipalFromToken(newToken);
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
            catch(Exception ex)
            {
                context.Result = new UnauthorizedObjectResult(ex.Message);
            }           
        }
        
        public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
        {
            //throw new NotImplementedException();
            return this;
        }

        private async Task<bool> IsAntiForgeryValid(AuthorizationFilterContext context)
        {
            bool isValid = true;   
            if (!context.IsEffectivePolicy<IAntiforgeryPolicy>(this))
            {
                isValid= false;
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

        private static bool HasAllowAnonymous(IList<IFilterMetadata> filters)
        {
            for (var i = 0; i < filters.Count; i++)
            {
                if (filters[i] is IAllowAnonymousFilter)
                {
                    return true;
                }
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

                // Authorization Header Flexibility
                // Authorization value start with "Bearer " then trim it off, else treat value as Token.
                token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
                tokenFound = true;
            }

            return tokenFound;
        }
    }
}
==================================================================
services.AddAzureAdAuthorization(Configuration);
services.AddScoped<SGAuthorizeFilter>();
=================================================================
using Microsoft.AspNetCore.Authorization;

namespace CrmValueObjects
{
    public class AuthorizeData : IAuthorizeData
    {
        public AuthorizeData(){}
        public AuthorizeData(string policy)
        {
            this.Policy = policy;
        }
        public string Policy { get; set; }
        public string Roles { get; set; }
        public string AuthenticationSchemes { get; set; }
    }
}
==================================================================
HttpPost("[Action]")]
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
=================================================================================
[HttpPost("[action]")]
        [AzureAdAuthFilter]
        public dynamic CommonFormExecutor([FromForm]MyRtmFormRequest<dynamic> rtmRequest)
        {
            try
            {
                var form = HttpContext.Request.Form;
                //var files = form.Files[0];
                //var data = form["data"];
                //var msg = await _client.PostAsync<string>("commonapi/CommonFormExecuter", form.Files.GetEnumerator(), form["Operation"], form["data"]);
                //return JsonConvert.DeserializeObject(msg);
            }
            catch (Exception ex)
            {
                
            }
            return Content("File upload");
        }
==================================================================================
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
=====================================================================
https://code-maze.com/upload-files-dot-net-core-angular/
https://dottutorials.net/dotnet-core-web-api-multipart-form-data-upload-file/
https://docs.microsoft.com/en-us/aspnet/core/mvc/models/file-uploads?view=aspnetcore-3.1