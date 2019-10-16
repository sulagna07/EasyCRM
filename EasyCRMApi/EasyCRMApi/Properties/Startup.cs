using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.Tasks;

namespace TestCaveSepApi
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

            services.AddControllers();
            var authority = Configuration["OktaConfig:Issuer"];

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            authority + Configuration["OktaConfig:OpenidEndpoint"],
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever());
            /*services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "bearer";
                options.DefaultChallengeScheme = "bearer";
            }).AddJwtBearer("bearer", options =>
            {
                // Configuration for your custom
                // JWT tokens here
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = "abc.com",//Configuration["Jwt:Issuer"],
                    ValidAudience = "abc.com",//Configuration["Jwt:Issuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                    ClockSkew = TimeSpan.Zero //the default for this setting is 5 minutes
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });*/

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = authority;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = authority,
                    ValidAudience = "api://default",
                    //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))
                    IssuerSigningKeyResolver = (token, securityToken, identifier, parameters) =>
                    {
                        var discoveryDocument = Task.Run(() => configurationManager.GetConfigurationAsync()).GetAwaiter().GetResult();
                        return discoveryDocument.SigningKeys;
                    }
                };
            })
            .AddJwtBearer("CustomJwt", options =>
            {
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
            });
            services.AddAuthorization(options =>
            {
                var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(
                    JwtBearerDefaults.AuthenticationScheme,
                    "CustomJwt");
                defaultAuthorizationPolicyBuilder =
                    defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
                options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

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
/*
https://docs.microsoft.com/en-us/aspnet/core/security/authorization/limitingidentitybyscheme?view=aspnetcore-3.0&tabs=aspnetcore2x
https://medium.com/agilix/asp-net-core-supporting-multiple-authorization-6502eb79f934
https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-3.0
https://github.com/aspnet/AspNetCore.Docs/blob/master/aspnetcore/security/anti-request-forgery/sample/AngularSample/Startup.cs
https://www.c-sharpcorner.com/article/preventing-csrf-attacks-in-asp-net-core-2-0/
https://stackoverflow.com/questions/42227254/how-to-prevent-csrf-xsrf-in-asp-net-core-mvc-app-web-api-controller
https://dzone.com/articles/secure-net-core-applications-from-csrf-attack-net
http://www.dotnet-stuff.com/tutorials/aspnet-core/preventing-cross-site-request-forgery-xsrf-csrf-atacks-in-asp-net-core
*/
