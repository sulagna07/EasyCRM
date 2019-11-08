using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RtmWebApi.Helper
{
    public class AuthorizeFilter : IAsyncAuthorizationFilter, IFilterFactory
    {
        private MvcOptions _mvcOptions;
        private AuthorizationPolicy _effectivePolicy;
        private readonly IAntiforgery _antiforgery;

        /// <summary>
        /// Initializes a new <see cref="AuthorizeFilter"/> instance.
        /// </summary>
        public AuthorizeFilter(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;
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
            try
            {
                await _antiforgery.ValidateRequestAsync(context.HttpContext);
            }
            catch (AntiforgeryValidationException exception)
            {
                //_logger.AntiforgeryTokenInvalid(exception.Message, exception);
                context.Result = new BadRequestResult();
            }
            // Allow Anonymous skips all authorization
            if (HasAllowAnonymous(context.Filters))
            {
                return;
            }
            var validToken = false;

            if (TokenExists(context, out string token))
            {
                try
                { validToken = await ValidateTokenAsync(token); } // This section can be greatly expanded to give more custom error messages.
                catch (SecurityTokenExpiredException) { /* Handle */ }
                catch (SecurityTokenValidationException) { /* Handle */ }
                catch (SecurityTokenException) { /* Handle */ }
                catch (Exception) { /* Handle */ }

                if (validToken) // Happy Path For Valid JWT
                {
                    //response = await base.SendAsync(request, cancellationToken);
                    //context.Result = new BadRequestResult();
                }
                else
                {
                    //response.StatusCode = HttpStatusCode.Unauthorized;
                    context.Result = new BadRequestResult();
                }
            }
            else // Optional Public access as Anonymous
            {
                // response.StatusCode = HttpStatusCode.Unauthorized;
                // response = await base.SendAsync(request, cancellationToken);
                context.Result = new BadRequestResult();
            }
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

        private async Task<bool> ValidateTokenAsync(string token)
        {
            var userIsValid = true; // assumed user is good (but could be false)
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            var tvp = GetTokenValidationParameters();

            //Extract and assigns the PrincipalId from JWT User/Claims.
             var clm= jwtSecurityTokenHandler.ValidateToken(token, tvp, out SecurityToken securityToken);//HttpContext.Current.User

            // TODO: Extra Validate the UserId, check for user still exists, user isn't banned, user registered email etc.
            //userIsValid = await _userService.ApiUserGetValidationAsync(HttpContext.Current.User.GetUserId());
            // GetUserId() is an extension method I wrote so you will need to write something like
            //this for yourself.

            if (!userIsValid) throw new SecurityTokenValidationException();

            return await Task.FromResult(userIsValid);
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
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
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

            // Additional checks can be performed on the SecurityToken or the validationParameters.
            if ((expires.HasValue && DateTime.UtcNow < expires)
             && (notBefore.HasValue && DateTime.UtcNow > notBefore))
            { valid = true; }

            return valid;
        }
    }
}

======================================================
public class ValidateAntiforgeryTokenAuthorizationFilter : IAsyncAuthorizationFilter, IAntiforgeryPolicy
    {
        private readonly IAntiforgery _antiforgery;
        private readonly ILogger _logger;

        public ValidateAntiforgeryTokenAuthorizationFilter(IAntiforgery antiforgery, ILoggerFactory loggerFactory)
        {
            if (antiforgery == null)
            {
                throw new ArgumentNullException(nameof(antiforgery));
            }

            _antiforgery = antiforgery;
            _logger = loggerFactory.CreateLogger(GetType());
        }

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.IsEffectivePolicy<IAntiforgeryPolicy>(this))
            {
               // _logger.NotMostEffectiveFilter(typeof(IAntiforgeryPolicy));
                return;
            }

            if (ShouldValidate(context))
            {
                try
                {
                    await _antiforgery.ValidateRequestAsync(context.HttpContext);
                }
                catch (AntiforgeryValidationException exception)
                {
                    //_logger.AntiforgeryTokenInvalid(exception.Message, exception);
                    context.Result = new BadRequestResult();
                }
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
    }
}
==============================================================================


namespace RtmsWebApi
{
    public class Startup
    {
        private static string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddDataProtection().DisableAutomaticKeyGeneration();
            services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(@"C:\DataKey")).DisableAutomaticKeyGeneration();//.SetApplicationName("my-app")
                //.ProtectKeysWithCertificate("thumbprint");
            
            
            services.AddControllers();
            

            // Angular's default header name for sending the XSRF token.
            services.AddAntiforgery(options =>
            {
                options.HeaderName = "X-XSRF-TOKEN";
            });
            services.AddScoped<AuthorizeFilter>();
            services.AddScoped<XSRFCookieFilter>();
            services.AddScoped<ValidateAntiforgeryTokenAuthorizationFilter>();
            services.AddScoped<RedirectAntiforgeryValidationFailedResultFilter>();
            //services.AddMvc(options => options.Filters.Add(new ValidateAntiForgeryTokenAttribute()));
            services.AddSingleton<IApiClient, ApiClient>();
            services.AddSingleton<IGenRefreshToken, GenRefreshToken>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IAntiforgery antiforgery)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            //app.UseAntiforgeryToken();
            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

=============================================================
https://github.com/aspnet/Mvc/blob/master/src/Microsoft.AspNetCore.Mvc.Core/Authorization/AuthorizeFilter.cs
https://stackoverflow.com/questions/31464359/how-do-you-create-a-custom-authorizeattribute-in-asp-net-core
https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.antiforgery.iantiforgeryadditionaldataprovider.validateadditionaldata?view=aspnetcore-3.0
