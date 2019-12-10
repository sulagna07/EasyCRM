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
public class SGBrandFilter : IActionFilter
    {
        private readonly IConfiguration _config;
        public SGBrandFilter(IConfiguration config)
        {
            _config = config;
        }

        public void OnActionExecuted(ActionExecutedContext context)
        {
            //throw new NotImplementedException();
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            if (context.ModelState.IsValid)
                {
                try
                {
                    var clientIp = context.HttpContext.Connection.RemoteIpAddress.ToString();
                    var brandUrl = context.HttpContext.Request.Host.Host;
                    var isModelExist = context.ActionArguments.TryGetValue("rtmRequest", out object requsetmodel);
                    if(!string.IsNullOrEmpty(clientIp) && !string.IsNullOrEmpty(brandUrl) && isModelExist)
                    {
                        var loginModel = requsetmodel as MyRtmRequest<dynamic>;
                        loginModel.UserData.RequestIP = clientIp;
                        loginModel.UserData.Brand = GetBrandName(brandUrl);
                    }
                    else
                    {
                        context.Result = new BadRequestResult();
                    }
                } 
                catch (Exception ex)
                {
                    context.Result = new BadRequestResult();
                }
            }
            else
            {
                context.Result = new BadRequestObjectResult(context.ModelState);
            }
        }

        private string GetBrandName(string brandurl)
        {
            var contentRoot = _config.GetValue<string>(WebHostDefaults.ContentRootKey);
            var jsonConfig = new ConfigurationBuilder().AddJsonFile(contentRoot+_config["BrandMapPath"]).Build();
            return jsonConfig["BrandUrl:"+ brandurl];
        }
    }
}
[ServiceFilter(typeof(SGBrandFilter))]
