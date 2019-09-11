import { Injectable } from '@angular/core';
import {HttpEvent,HttpHandler,HttpInterceptor,HttpRequest} from '@angular/common/http';
import { Observable } from 'rxjs';
import { from } from 'rxjs';
import { OktaAuthService } from '@okta/okta-angular';
import { UserService } from './user.service';

@Injectable({
  providedIn: 'root'
})
export class AuthInterceptor implements HttpInterceptor {
  constructor(private oktaAuth: OktaAuthService, private userService: UserService) { }

  intercept(request: HttpRequest<any>,next: HttpHandler): Observable<HttpEvent<any>> {
    return from(this.handleLohaAccess(request, next));//Observable.fromPromise(this.handleAccess(request, next));
  }

  private async handleLohaAccess(request: HttpRequest<any>, next: HttpHandler): Promise<HttpEvent<any>> {
    const accessToken = await this.oktaAuth.getAccessToken();
    const currentUser = this.userService.currentUserValue;
    console.log(currentUser);
    var authString: string='';
    if (currentUser && currentUser.token) {
      authString = `Bearer ${currentUser.token}`;
    } else if (accessToken) {
      authString = `Bearer ${accessToken}`; //'Bearer ' + accessToken;
    }
    console.log("Auth head", authString)
    request = request.clone({
      setHeaders: {
        Authorization: authString
      }
    });
    return next.handle(request).toPromise();
  }
}

=================================================================
import { Component, OnInit } from '@angular/core';
import { UserService } from '../shared/user.service';
import { FormBuilder, Validators, FormGroup } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  public loginForm: FormGroup;
  returnUrl: string;

  constructor(private formbulider: FormBuilder, private userService: UserService,
    private router: Router, private route: ActivatedRoute, ) {
    // redirect to home if already logged in
    if (this.userService.currentUserValue) {
      this.router.navigate(['/']);
    }
  }

  ngOnInit() {
    this.loginForm = this.formbulider.group({
      UserName: ['', [Validators.required]],
      Password: ['', [Validators.required]]
    });
  }

  onAccountLogin() {
    const loginInfo = this.loginForm.value;
    this.userService.AccountLogin(loginInfo).subscribe(
      data => {
        this.router.navigate(['/']);
      }
    );
  }

}
==============================================================
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "AllowedHosts": "*",
  "OktaConfig": {
    "Issuer": "https://dev-345075.okta.com/oauth2/default",
    "OpenidEndpoint": "/.well-known/openid-configuration"
  },
  "PDFSettings": "files/692631.pdf",
  "Jwt": {
    "Key": "ThisismyPrivateSecretKey",
    "Issuer": "abc.com"
  }
}

===========================================================
import { Injectable, Inject} from '@angular/core';
import { HttpHeaders } from '@angular/common/http';
import { HttpClient } from '@angular/common/http'
import { ResponseContentType } from '@angular/http';
import { Observable, BehaviorSubject } from 'rxjs';
import { map } from 'rxjs/operators';
import { CRMResponse, AccountLogin, AccountUser } from '../models/account-login';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  private currentUserSubject: BehaviorSubject<AccountUser>;
  public currentUser: Observable<AccountUser>;

  constructor(private http: HttpClient, @Inject('BASE_URL') private baseUrl: string) {
    this.currentUserSubject = new BehaviorSubject<AccountUser>(JSON.parse(localStorage.getItem('currentUser')));
    this.currentUser = this.currentUserSubject.asObservable();
  }

  AccountLogin(accountLoginModel: AccountLogin): Observable<CRMResponse> {
    console.log(accountLoginModel);
    console.log(this.baseUrl);
    const httpOptions = { headers: new HttpHeaders({ 'Content-Type': 'application/json' }) };
    return this.http.post<CRMResponse>(this.baseUrl + 'api/login/login',
      accountLoginModel, httpOptions).pipe(map(resp => {
        // login successful if there's a jwt token in the response
        console.log("resp",resp);
        if (resp.success) {
          localStorage.setItem('currentUser', JSON.stringify(resp.data));
          this.currentUserSubject.next(resp.data);
        }
        return resp;
      }));
  }

  public get currentUserValue(): AccountUser {
    return this.currentUserSubject.value;
  }

}

=========================================================================
var authority = Configuration["OktaConfig:Issuer"];

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            authority + Configuration["OktaConfig:OpenidEndpoint"],
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever());
            
            services.AddAuthentication()
            .AddJwtBearer("OktaJwt", options =>
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
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Issuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))
                };
            });

            services
                .AddAuthorization(options =>
                {
                    options.DefaultPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .AddAuthenticationSchemes("OktaJwt", "CustomJwt")
                        .Build();
                });
				
=======================================================================
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using ValueObjects;

namespace LohaWeb.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;
        public LoginController(IConfiguration config)
        {
            _config = config;
        }
        [HttpPost("login")]
        public async Task<string> Login([FromBody]UserModel login)
        {
            LohaResponse<AccountUser> resp = new LohaResponse<AccountUser>();
            var user = AuthenticateUser(login);
            if (user != null)
            {
                AccountUser auser = new AccountUser();
                auser.FullName = "Jhon Doe";
                auser.Email = "Test@test.com";
                auser.Token= GenerateJSONWebToken(user);
                resp.Data = auser;
                resp.Success = true;
            }
            else
            {
                resp.Message = "error";
                resp.Success = false;
            }
            return JsonConvert.SerializeObject(resp, new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() });
            //return resp;
        }

        private string GenerateJSONWebToken(UserModel userInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, userInfo.Username),
                new Claim(JwtRegisteredClaimNames.Email, userInfo.EmailAddress),
                new Claim("DateOfJoing", userInfo.DateOfJoing.ToString("yyyy-MM-dd")),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
            _config["Jwt:Issuer"],
            claims,
            expires: DateTime.Now.AddMinutes(120),
            signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = null;

            if (login.Username == "Jignesh")
            {
                user = new UserModel { Username = "Jignesh Trivedi", EmailAddress = "test.btest@gmail.com" };
            }
            return user;

        }
    }

    public class UserModel
    {
        public string Username { get; set; }
        public string EmailAddress { get; set; }
        public string Password { get; set; }
        public DateTime DateOfJoing { get; set; }
    }

    public class AccountUser
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
    }
}
==============================================================================================================
export class AccountLogin {
  UserName: string;
  Password: string;
}

export class CRMResponse {
  success: boolean;
  message: string;
  data: any;
}

export class AccountUser {
  fullName: string;
  email: string;
  token: string;
}
=====================================================================
https://stackoverflow.com/questions/49694383/use-multiple-jwt-bearer-authentication
https://stackoverflow.com/questions/46520047/how-to-allow-multiple-jwt-with-different-issuers-in-asp-net-core-2-0
https://jasonwatmore.com/post/2019/01/08/aspnet-core-22-role-based-authorization-tutorial-with-example-api
https://docs.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-2.2
