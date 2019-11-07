import { Injectable } from '@angular/core';
import {HttpEvent,HttpHandler,HttpInterceptor,HttpRequest, HttpErrorResponse} from '@angular/common/http';
import { Observable } from 'rxjs';
import { from } from 'rxjs';
import { CookieService } from 'ngx-cookie-service';
import { AuthenticationService } from '../_services/authentication.service';
import { tap } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class AuthInterceptor implements HttpInterceptor {
    constructor(private authenticationService: AuthenticationService, private cookieService: CookieService) { }

  /*intercept(request: HttpRequest<any>,next: HttpHandler): Observable<HttpEvent<any>> {
    return from(this.handleLohaAccess(request, next));
  }*/
    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        // add authorization header with jwt token if available
        let currentUser = this.authenticationService.currentUserValue;
        let xsToken = this.cookieService.get('XSRF-TOKEN');
        console.log("currentUser", currentUser);
        console.log("xsToken", xsToken);
        if (xsToken && currentUser && currentUser.token) {
            request = request.clone({
                setHeaders: {
                    Authorization: `Bearer ${currentUser.token}`,
                    'X-XSRF-TOKEN': xsToken
                }
            });
        }
        else if (currentUser && currentUser.token) {
            request = request.clone({
                setHeaders: {
                    Authorization: `Bearer ${currentUser.token}`
                }
            });
        }

        //return next.handle(request);
        return next.handle(request)
            .pipe(
                tap(
                    (result: HttpEvent<any>) => console.log("response intercepted", result),
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

==========================================================================
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using RtmWebApi.Helper;

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
            services.AddAuthentication(options =>
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
                    ValidIssuer = "abc.com",
                    ValidAudience = "abc.com",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret)),
                    ClockSkew = TimeSpan.Zero //the default for this setting is 5 minutes
                };
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Add("Access-Control-Expose-Headers", "Token-Expired");
                            context.Response.Headers.Add("Token-Expired", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            // Angular's default header name for sending the XSRF token.
            services.AddAntiforgery(options =>
            {
                options.HeaderName = "X-XSRF-TOKEN";
            });
            services.AddMvc(options => options.Filters.Add(new ValidateAntiForgeryTokenAttribute()));
            services.AddSingleton<IApiClient, ApiClient>();
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
[HttpPost("[Action]")]
        [IgnoreAntiforgeryToken]
        public IActionResult GenerateAntiForgeryTokens()
        {
            var tokens = _antiForgery.GetAndStoreTokens(HttpContext);
            Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken, new Microsoft.AspNetCore.Http.CookieOptions
            {
                HttpOnly = false
            });
            return NoContent();
        }

        [HttpPost("[Action]")]
        [AllowAnonymous]
        [IgnoreAntiforgeryToken]
        public IActionResult UserLogin(UserLoginModel userParam)
        {
            var user = Authenticate(userParam.UserName, userParam.Password);

            if (user == null)
                return NotFound();//BadRequest(new { message = "Username or password is incorrect" });

            return Ok(user);
        }
======================================================================================
import { Injectable, Inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { User } from '../_models/user';


@Injectable({
    providedIn: 'root'
})
export class AuthenticationService {

    private currentUserSubject: BehaviorSubject<User>;
    public currentUser: Observable<User>;

    constructor(private http: HttpClient, @Inject('BASE_URL') private baseUrl: string) {
        this.currentUserSubject = new BehaviorSubject<User>(JSON.parse(localStorage.getItem('currentUser')));
        this.currentUser = this.currentUserSubject.asObservable();
    }

    public get currentUserValue(): User {
        return this.currentUserSubject.value;
    }

    login(username: string, password: string) {
        let reqObj = {
            "UserName": username,
            "Password": password
        };
        return this.http.post<any>(this.baseUrl + 'rtmsapi/api/login/userlogin', reqObj)
            .pipe(map(user => {
                // store user details and jwt token in local storage to keep user logged in between page refreshes
                localStorage.setItem('currentUser', JSON.stringify(user));
                this.currentUserSubject.next(user);
                return user;
            }),switchMap(_ => this.http.post<any>(this.baseUrl + 'rtmsapi/api/login/generateantiforgerytokens', ''))
        );
    }

    logout() {
        // remove user from local storage to log user out
        localStorage.removeItem('currentUser');
        this.currentUserSubject.next(null);
    }
}
==================================================================
https://www.dotnetcurry.com/angularjs/1448/angular-http-client-interceptors-headers-event
https://stackoverflow.com/questions/48184107/read-response-headers-from-api-response-angular-5-typescript
https://stackoverflow.com/questions/14970102/anti-forgery-token-is-meant-for-user-but-the-current-user-is-username
https://code-maze.com/action-filters-aspnetcore/
https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/filters?view=aspnetcore-3.0
https://forums.asp.net/t/1938599.aspx?How+to+extend+the+functionality+of+Anti+forgery+token+class
https://nozzlegear.com/blog/send-and-validate-an-asp-net-antiforgerytoken-as-a-request-header
http://www.prideparrot.com/blog/archive/2012/7/securing_all_forms_using_antiforgerytoken
https://andrewlock.net/introduction-to-authentication-with-asp-net-core/
https://github.com/aspnet/AspNetCore/issues/3616

