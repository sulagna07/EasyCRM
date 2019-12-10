public IActionResult OktaAuthorize()
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return Challenge(OpenIdConnectDefaults.AuthenticationScheme);
            }
            return RedirectToAction("Privacy", "OktaAuth");
        }
=============================================
services.AddAuthentication(options =>
{
	options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie()
.AddOpenIdConnect(options =>
{
	
	options.Authority = Configuration["Okta:Domain"] + "/oauth2/default";
	options.RequireHttpsMetadata = false; //true
	options.ClientId = Configuration["Okta:ClientId"];
	options.ClientSecret = Configuration["Okta:ClientSecret"];
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
===============================================
services.AddAuthentication(options =>
{
	// If an authentication cookie is present, use it to get authentication information
	options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
	options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

	// If authentication is required, and no cookie is present, use Okta (configured below) to sign in
	options.DefaultChallengeScheme =  "Okta"; //OktaDefaults.ApiAuthenticationScheme;
})
.AddCookie() // cookie authentication middleware first
.AddOAuth("Okta", options =>
{
	// Oauth authentication middleware is second

	var oktaDomain = Configuration.GetValue<string>("Okta:Domain");

	// When a user needs to sign in, they will be redirected to the authorize endpoint
	options.AuthorizationEndpoint = $"{oktaDomain}/oauth2/default/v1/authorize";

	// Okta's OAuth server is OpenID compliant, so request the standard openid
	// scopes when redirecting to the authorization endpoint
	options.Scope.Add("openid");
	options.Scope.Add("profile");
	options.Scope.Add("email");

	// After the user signs in, an authorization code will be sent to a callback
	// in this app. The OAuth middleware will intercept it
	options.CallbackPath = new PathString("/authorization-code/callback");

	// The OAuth middleware will send the ClientId, ClientSecret, and the
	// authorization code to the token endpoint, and get an access token in return
	options.ClientId = Configuration.GetValue<string>("Okta:ClientId");
	options.ClientSecret = Configuration.GetValue<string>("Okta:ClientSecret");
	options.TokenEndpoint = $"{oktaDomain}/oauth2/default/v1/token";

	// Below we call the userinfo endpoint to get information about the user
	options.UserInformationEndpoint = $"{oktaDomain}/oauth2/default/v1/userinfo";

	// Describe how to map the user info we receive to user claims
	options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
	options.ClaimActions.MapJsonKey(ClaimTypes.Name, "given_name");
	options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

	options.Events = new OAuthEvents
	{
		OnCreatingTicket = async context =>
		{
			// Get user info from the userinfo endpoint and use it to populate user claims
			var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
			request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

			var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
			response.EnsureSuccessStatusCode();

			var user = JsonSerializer.Deserialize<dynamic>(await response.Content.ReadAsStringAsync());

			context.RunClaimActions(user);
		}
	};
});
===================================================================================
"Okta": {
    "ClientId": "0oaohmhl1639uYtFL0h7",
    "ClientSecret": "KJeENRP-5WaltNJp6yqrF_MwyZA7sTISWgdK4rHg",
    "Domain": "https://dev-198806.oktapreview.com"

}
====================================================================================
https://developer.okta.com/blog/2018/04/18/authorization-in-your-aspnet-mvc-4-application
https://github.com/bbachi/angular-idle-timeout/blob/master/src/app/app.component.ts
https://blog.bitsrc.io/how-to-implement-idle-timeout-in-angular-af61eefdb13b
http://www.binaryintellect.net/articles/d56c7798-703d-45cf-be74-a8b0cec94a3c.aspx

====================================================================================
// sets an idle timeout of 5 seconds, for testing purposes.
    idle.setIdle(10);
    // sets a timeout period of 5 seconds. after 10 seconds of inactivity, the user will be considered timed out.
    idle.setTimeout(10);
    // sets the default interrupts, in this case, things like clicks, scrolls, touches to the document
    idle.setInterrupts(DEFAULT_INTERRUPTSOURCES);
    //idle.setInterrupts([new EventTargetInterruptSource(document.documentElement, "click")]);

    idle.onIdleEnd.subscribe(() => {
      localStorage.setItem('lastPing', Date.now().toString());
      this.childModal.hide();
      this.idleState = 'No longer idle.'
      console.log(this.idleState);
      this.reset();
    });

    idle.onTimeout.subscribe(() => {
      this.idleState = 'Timed out!';
      this.timedOut = true;
      console.log(this.idleState);
      this.logout();
    });

    idle.onIdleStart.subscribe(() => {
      var lastping = Number(localStorage.getItem('lastPing'));
      if (Date.now() - lastping > 10000) {
        localStorage.setItem('sessionTimeout', "true");
        this.idleState = 'You\'ve gone idle!'
        console.log(this.idleState);
        this.childModal.show();
      }
    });

    idle.onTimeoutWarning.subscribe((countdown) => {
      var sessionTimeout = Boolean(localStorage.getItem('sessionTimeout'));
      if (sessionTimeout) {

        this.idleState = 'You will time out in ' + countdown + ' seconds!'
        console.log(this.idleState);
      }
    });

    // sets the ping interval to 15 seconds
    //keepalive.interval(2);

    //keepalive.onPing.subscribe(() => { this.lastPing = new Date(); console.log("ping"); });

    this.authenticationService.currentUser.subscribe(x => {
      if (x) {
        localStorage.setItem('lastPing', Date.now().toString());
        this.currentUser = x;
        this.showNavBar = true;
        idle.watch()
        this.timedOut = false;
        localStorage.setItem('sessionTimeout', "false");
      } else {
        idle.stop();
      }
    });
    this.authenticationService.currentToken.subscribe(x => this.currentToken = x);
===============================================================================================
reset() {
    this.idle.watch();
    //xthis.idleState = 'Started.';
    this.timedOut = false;
    localStorage.setItem('sessionTimeout', "false");
  }

  hideChildModal(): void {
    this.childModal.hide();
  }

  stay() {
    this.childModal.hide();
    this.reset();
  }

  logout() {
    this.childModal.hide();
    this.authenticationService.logout();
    this.showNavBar = false;
    this.router.navigate(['/']);
  }
===================================================================================================
"@ng-idle/core": "^8.0.0-beta.4",
    "@ng-idle/keepalive": "^8.0.0-beta.4",
==============================================================================
USE [CricInfo]
GO
/****** Object:  StoredProcedure [dbo].[CricInfoRefresh_iu]    Script Date: 10-12-2019 09:27:41 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
ALTER PROCEDURE [dbo].[CricInfoRefresh_iu]
@JsonReq			NVARCHAR(max),
@ErrorMessage	VARCHAR(MAX)		OUTPUT

	

AS
SET NOCOUNT ON

DECLARE @JsonData			NVARCHAR(MAX)
DECLARE @ExceptionMessage	VARCHAR(MAX)
--SET @JsonData = '{"userName":"Admin","userId":1,"roleId":4,"officeId":"A01"}';

--BEGIN TRY
Insert into StoreToken SELECT AuthToken,RefreshToken,UserId,ExpiredAt
FROM OPENJSON(@JsonReq)
  WITH (
    AuthToken NVARCHAR(Max) 'strict $.Data.AuthToken',
    RefreshToken NVARCHAR(Max) '$.Data.RefreshToken',
    UserId varchar(10) '$.Data.UserId',
	ExpiredAt varchar(50) '$.Data.ExpiredAt'
  ); --FOR JSON PATH ;
--END TRY
/*BEGIN CATCH
	SET @ExceptionMessage='error found';
    RAISERROR (@ExceptionMessage,16, 1)
	SELECT  @ExceptionMessage
	--THROW 51000, @ErrorMess, 1
END CATCH*/
