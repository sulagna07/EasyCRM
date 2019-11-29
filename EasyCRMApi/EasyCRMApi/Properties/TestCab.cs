using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using SGAuthFilter.SGServices;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SGAuthFilter.SGFilter
{
    public class AuthorizeFilter : IAsyncAuthorizationFilter, IFilterFactory, IAntiforgeryPolicy
    {
        private readonly IAntiforgery _antiforgery;
        private readonly IAuthService _authService;

        /// <summary>
        /// Initializes a new <see cref="AuthorizeFilter"/> instance.
        /// </summary>
        public AuthorizeFilter(IAntiforgery antiforgery, IAuthService authService)
        {
            _antiforgery = antiforgery;
            _authService = authService;
        }
        
        /// <summary>
        /// The <see cref="IAuthorizationPolicyProvider"/> to use to resolve policy names.
        /// </summary>
        public IAuthorizationPolicyProvider PolicyProvider { get; }

        /// <summary>
        /// The <see cref="IAuthorizeData"/> to combine into an <see cref="IAuthorizeData"/>.
        /// </summary>
        public IEnumerable<IAuthorizeData> AuthorizeData { get; }

        /// <summary>
        /// Gets the authorization policy to be used.
        /// </summary>
        /// <remarks>
        /// If<c>null</c>, the policy will be constructed using
        /// <see cref="AuthorizationPolicy.CombineAsync(IAuthorizationPolicyProvider, IEnumerable{IAuthorizeData})"/>.
        /// </remarks>
        public AuthorizationPolicy Policy { get; }

        bool IFilterFactory.IsReusable => true;

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.IsEffectivePolicy<IAntiforgeryPolicy>(this))
            {
                return;
            }

            /*if (context.HttpContext.Request.HttpMethod != "POST")
                return;

            if (context.ActionDescriptor.GetCustomAttributes(typeof(NoAntiForgeryCheckAttribute), true).Length > 0)
                return;*/

            if (ShouldValidate(context))
            {
                try
                {
                    await _antiforgery.ValidateRequestAsync(context.HttpContext);
                }
                catch (AntiforgeryValidationException ex)//ex
                {
                    //_logger.AntiforgeryTokenInvalid(exception.Message, exception);
                    context.Result = new BadRequestResult();
                }
            }

            // Allow Anonymous skips all authorization
            if (HasAllowAnonymous(context.Filters))
            {
                return;
            }
            var validToken = false;
            ClaimsPrincipal userClaim = null;
            if (TokenExists(context, out string token))
            {
                try
                { 
                    validToken = ValidateTokenAsync(token, out userClaim); 
                } // This section can be greatly expanded to give more custom error messages.
                catch (SecurityTokenExpiredException) {
                    /* Handle */
                    userClaim = _authService.GetPrincipalFromToken(token);
                    context.HttpContext.Request.Cookies.TryGetValue("Refresh-Token",out string oldRefToken);
                    //call db
                    var newToken = _authService.CreateRefreshToken(userClaim);
                    var newRefToken = _authService.GenerateRefreshToken();
                    context.HttpContext.Response.Headers.Add("Auth-Token", newToken);
                    context.HttpContext.Response.Cookies.Delete("Refresh-Token");
                    context.HttpContext.Response.Cookies.Append("Refresh-Token", newRefToken, new CookieOptions
                    {
                        HttpOnly = true
                    });

                    context.HttpContext.Response.Cookies.Delete("XSRF-TOKEN");
                    var tokens = _antiforgery.GetAndStoreTokens(context.HttpContext);
                    context.HttpContext.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new CookieOptions
                    {
                        HttpOnly = false
                    });
                    validToken = true;
                }
                catch (SecurityTokenValidationException) { /* Handle */ }
                catch (SecurityTokenException) { /* Handle */ }
                catch (Exception) { /* Handle */ }

                if (validToken && userClaim != null) // Happy Path For Valid JWT
                {
                    context.HttpContext.User = userClaim;
                }
                else
                {
                    context.Result = new UnauthorizedResult();
                }
            }
            else // Optional Public access as Anonymous
            {
                context.Result = new UnauthorizedResult();
            }
        }
        protected virtual bool ShouldValidate(AuthorizationFilterContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return true;
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

        public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
        {
            //throw new NotImplementedException();
            return this;
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

        private bool ValidateTokenAsync(string token, out ClaimsPrincipal userClaim)
        {
            var userIsValid = false; // assumed user is good (but could be false)
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            var tvp = GetTokenValidationParameters();

            //Extract and assigns the PrincipalId from JWT User/Claims.
            userClaim = jwtSecurityTokenHandler.ValidateToken(token, tvp, out SecurityToken securityToken);
            if (userClaim != null)
            {
                userIsValid = true;
            }

            // TODO: Extra Validate the UserId, check for user still exists, user isn't banned, user registered email etc.
            //userIsValid = await _userService.ApiUserGetValidationAsync(HttpContext.Current.User.GetUserId());
            // GetUserId() is an extension method I wrote so you will need to write something like
            //this for yourself.

            if (!userIsValid) throw new SecurityTokenValidationException();

            return userIsValid;
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
            // Cleanup
            return new TokenValidationParameters
            {

                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "abc.com",
                ValidAudience = "abc.com",
                LifetimeValidator = this.LifetimeValidator,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(Secret)),
                ClockSkew = TimeSpan.Zero //the default for this setting is 5 minutes


            };
        }

        private bool LifetimeValidator(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
        {
            var valid = false;
            var maxTokenGenTime = expires.Value.AddMinutes(1);
            // Additional checks can be performed on the SecurityToken or the validationParameters.
            if ((expires.HasValue && DateTime.UtcNow < expires.Value) && (notBefore.HasValue && DateTime.UtcNow > notBefore))
            { 
                return true; 
            }
            else if ((expires.HasValue && DateTime.UtcNow < maxTokenGenTime) && (notBefore.HasValue && DateTime.UtcNow > notBefore))
            {
                throw new SecurityTokenExpiredException();
            }
            return valid;
        }
    }
}
==============================================================
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
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

        public string CreateToken(UserClaimModel userModel)
        {
            // return null if user not found
            if (userModel == null)
                return null;

            // authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["AuthConfig:SecretKey"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    //new Claim("sub", userModel.UserName),
                    new Claim(ClaimTypes.UserData, EncryptString(JsonSerializer.Serialize(userModel)))
                }, JwtBearerDefaults.AuthenticationScheme,"name","role"),
                NotBefore = DateTime.UtcNow,
                Audience = _config["AuthConfig:Audiance"],
                Issuer = _config["AuthConfig:Issuer"],
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["AuthConfig:TokenExpire"])),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);

        }

        public string GenerateRefreshToken()
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
            return principal;
        }

        public string CreateRefreshToken(ClaimsPrincipal userClaims)
        {
            // return null if user not found
            if (userClaims == null)
                throw new SecurityTokenException();

            // authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["AuthConfig:SecretKey"]);
            
                /*ClaimsIdentity identityx = null;
                try
                {
                    identityx = (ClaimsIdentity)userClaims.Identity;
                    Claim usernameClaim = identityx.FindFirst(ClaimTypes.UserData);
                }
                catch (NullReferenceException)
                {
                    
                }*/
            try
            {

                ClaimsIdentity identity = (ClaimsIdentity)userClaims.Identity;
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                    {
                    new Claim("sub", identity.FindFirst(ClaimTypes.UserData).Value),
                    }, JwtBearerDefaults.AuthenticationScheme,"name","role"),
                    NotBefore = DateTime.UtcNow,
                    Audience = _config["AuthConfig:Audiance"],
                    Issuer = _config["AuthConfig:Issuer"],
                    Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["AuthConfig:TokenExpire"])),

                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(token);
            }
            catch(Exception ex)
            {
                throw new Exception();
            }
            
        }
        private string EncryptString(string encryptString)
        {
            string EncryptionKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            byte[] clearBytes = Encoding.ASCII.GetBytes(encryptString);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
            0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
            });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    encryptString = Convert.ToBase64String(ms.ToArray());
                }
            }
            return encryptString;
        }
        private string DecryptString(string cipherText)
        {
            string EncryptionKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
            0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
            });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.ASCII.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
    }
}
===================================================================
   [HttpPost("[Action]")]
        [AllowAnonymous]
        [ServiceFilter(typeof(XSRFCookieFilter))]
        [ServiceFilter(typeof(SGBrandFilter))]
        public async Task<IActionResult> UserLogin(MyRtmLoginRequest<dynamic> rtmRequest)
        {
            //var cn = HttpContext;
            //rtmRequest.IsChacheRequired = _cacheHelper.CachePopulationRequired();
            var data = await _apiClient.PostAsync<MyRtmResponse<BusinessData<dynamic>>, MyRtmLoginRequest<dynamic>>("weatherforecast/GetLoginData", rtmRequest);//MyRtmResponse<dynamic>
            if (data.Success)
            {
                var clm = CommonService.DeserializeString<UserClaimModel>(data.BusinessData.Data.ToString()) as UserClaimModel;// data.BusinessData.Data as UserClaimModel;
                var authToken = _authService.CreateToken(clm);//CommonService.DeserializeString<UserClaimModel>(data.Data)
                var refreshToken = _authService.GenerateRefreshToken();
                rtmRequest.Data = new ReTokenModel {AuthToken= authToken ,RefreshToken= refreshToken ,UserId=clm.UserId, ExpiredAt= DateTime.UtcNow.AddDays(1).ToString() };
                //rtmRequest.Data="{\"AuthToken\":\""+authToken+"\",\"RefreshToken\":\""+refreshToken+ "\",\"UserId\":" + clm.UserId + ",\"ExpiredAt\":\"" + DateTime.UtcNow.AddDays(1) + "\"}";
                rtmRequest.Operation = "StoreRefresh";
                rtmRequest.UserData = null;
                var rdata= await _apiClient.PostAsync<MyRtmResponse<BusinessData<dynamic>>, MyRtmLoginRequest<dynamic>>("weatherforecast/GetLoginData", rtmRequest);
                Response.Headers.Add("Auth-Token", authToken);

                Response.Cookies.Append("Refresh-Token", refreshToken, new CookieOptions
                {
                    HttpOnly = true
                });
                return Ok(data);
            }
            return NotFound(data);
        }
    }