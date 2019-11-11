public class AuthorizeFilter : IAsyncAuthorizationFilter, IFilterFactory, IAntiforgeryPolicy
    {
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
                catch (AntiforgeryValidationException)//ex
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

            if (TokenExists(context, out string token))
            {
                try
                { 
                    validToken = await ValidateTokenAsync(token); 
                } // This section can be greatly expanded to give more custom error messages.
                catch (SecurityTokenExpiredException) {
                    /* Handle */
                    var udata=Authenticate("admin","admin");
                    context.HttpContext.Response.Headers.Add("Auth-Token", udata.Token);
                    context.HttpContext.Response.Cookies.Delete("XSRF-TOKEN");
                    var tokens = _antiforgery.GetAndStoreTokens(context.HttpContext);
                    context.HttpContext.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new Microsoft.AspNetCore.Http.CookieOptions
                    {
                        HttpOnly = false
                    });
                    validToken = true;
                }
                catch (SecurityTokenValidationException) { /* Handle */ }
                catch (SecurityTokenException) { /* Handle */ }
                catch (Exception) { /* Handle */ }

                if (validToken) // Happy Path For Valid JWT
                {
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
            var maxTokenGenTime = expires.Value.AddMinutes(2);
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

        private User Authenticate(string username, string password)
        {
            List<User> _users = new List<User>
            {
            new User { Id = 1, FirstName = "Admin", LastName = "User", Username = "admin", Password = "admin", Role = Role.Admin },
            new User { Id = 2, FirstName = "Normal", LastName = "User", Username = "user", Password = "user", Role = Role.User }
            };
            string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
            var user = _users.SingleOrDefault(x => x.Username == username && x.Password == password);
            // return null if user not found

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
                NotBefore = DateTime.UtcNow,
                Audience = "abc.com",
                Issuer = "abc.com",
                Expires = DateTime.UtcNow.AddMinutes(2),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.WriteToken(token);

            // remove password before returning
            user.Password = null;

            return user;
        }
    }
==============================================================================
login(username: string, password: string) {
        let reqObj = {
            "UserName": username,
            "Password": password
        };
        return this.http.post<any>(this.baseUrl + 'rtmsapi/api/login/userlogin', reqObj)
            .pipe(map(user => {
                // store user details and jwt token in local storage to keep user logged in between page refreshes
                console.log(user);
                localStorage.setItem('currentUser', JSON.stringify(user));
                this.currentUserSubject.next(user);
                return user;
            })//,switchMap(_ => this.http.post<any>(this.baseUrl + 'rtmsapi/api/login/generateantiforgerytokens', ''))
        );
    }

    refreshToken(token: string) {
        localStorage.removeItem('currentToken');
        this.currentTokenSubject.next(null);
        localStorage.setItem('currentToken', token);
        this.currentTokenSubject.next(token);
        console.log("refreshed", token);
    }
==================================================================================
@Injectable()
export class ErrorInterceptor implements HttpInterceptor {
    constructor(private authenticationService: AuthenticationService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    return next.handle(request)
        .pipe(
            tap(
                (result: HttpResponse<any>) => {
                    console.log("response intercepted", result);
                    if (result.headers != null && result.headers.has("Auth-Token")) {

                        this.authenticationService.refreshToken(result.headers.get("Auth-Token"));
                    }
                    
                },
                (error: HttpErrorResponse) => {
                    console.error("error response intercepted", error);
                    if (error.headers.has('Token-Expired') && error.status == 401) {
                        console.log("Token expired");
                    }
                }
            )
        );
    }
}
==================================================================

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

        public string EncryptString(string encryptString)
        {
            string EncryptionKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            byte[] clearBytes = Encoding.Unicode.GetBytes(encryptString);
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

        public string DecryptString(string cipherText)
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
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
===================================================================================

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
https://github.com/aspnet/Mvc/blob/master/src/Microsoft.AspNetCore.Mvc.Core/Authorization/AuthorizeFilter.cs
https://stackoverflow.com/questions/31464359/how-do-you-create-a-custom-authorizeattribute-in-asp-net-core
https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.antiforgery.iantiforgeryadditionaldataprovider.validateadditionaldata?view=aspnetcore-3.0

