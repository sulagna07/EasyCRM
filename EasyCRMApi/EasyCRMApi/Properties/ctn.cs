routes.MapRoute(
                    name: "areas",
                    template: "{area:exists}/{controller=Home}/{action=Index}/{id?}"
                );
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}"
                );
===================
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace HBAuthTest.Controllers
{
    [Route("external/[controller]")]
    public class OktaLoginController : Controller
    {
        /*[HttpPost("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            var userClaims = HttpContext.User.Claims;
            return Content("Test");
        }*/

        /*[HttpGet("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            Resource res = new User();
            var userClaims = HttpContext.User.Claims;
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                //return Content("Test2");
                return Challenge(OktaDefaults.MvcAuthenticationScheme);
            }
            return Content("Test3");
            
        }*/

        [HttpGet("[action]")]
        public IActionResult Index()
        {
            var iden = HttpContext.User.Identity;
            //Resource res = new User();
            var userClaims = HttpContext.User.Claims;
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                var dt=new OktaTokenService().GetToken();
                return Content("Test3");
            }
            return Content("Test4");
        }
    }
    public class OktaTokenService //: ITokenService
    {
        private OktaToken token = new OktaToken();
        //private readonly IOptions<OktaSettings> oktaSettings;

        /*public OktaTokenService(IOptions<OktaSettings> oktaSettings)
        {
            this.oktaSettings = oktaSettings;
        }*/

        public async Task<string> GetToken()
        {
            if (!this.token.IsValidAndNotExpiring)
            {
                this.token = await this.GetNewAccessToken();
            }
            return token.AccessToken;
        }

        private async Task<OktaToken> GetNewAccessToken()
        {
            var token = new OktaToken();
            var client = new HttpClient();
            var client_id = "0oan";//this.oktaSettings.Value.ClientId;
            var client_secret = "h7EkLQ81o0sV0s1UItSXevlDR";//this.oktaSettings.Value.ClientSecret;
            var clientCreds = System.Text.Encoding.UTF8.GetBytes($"{client_id}:{client_secret}");
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Basic", System.Convert.ToBase64String(clientCreds));

            var postMessage = new Dictionary<string, string>();
            postMessage.Add("grant_type", "client_credentials");
            postMessage.Add("scope", "access_token");
            var request = new HttpRequestMessage(HttpMethod.Post, "https://dev-198806.oktapreview.com/oauth2/default/v1/token")//  this.oktaSettings.Value.TokenUrl
            {
                Content = new FormUrlEncodedContent(postMessage)
            };

            var response = await client.SendAsync(request);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                token = JsonConvert.DeserializeObject<OktaToken>(json);
                token.ExpiresAt = DateTime.UtcNow.AddSeconds(this.token.ExpiresIn);
            }
            else
            {
                throw new ApplicationException("Unable to retrieve access token from Okta");
            }

            return token;
        }

    }

    public class OktaToken
    {
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        [JsonProperty(PropertyName = "expires_in")]
        public int ExpiresIn { get; set; }

        public DateTime ExpiresAt { get; set; }

        public string Scope { get; set; }

        [JsonProperty(PropertyName = "token_type")]
        public string TokenType { get; set; }

        public bool IsValidAndNotExpiring
        {
            get
            {
                return !String.IsNullOrEmpty(this.AccessToken) &&
          this.ExpiresAt > DateTime.UtcNow.AddSeconds(30);
            }
        }
    }
}
====================================================================
         services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OktaDefaults.MvcAuthenticationScheme;
            })
.AddCookie()
.AddOktaMvc(new OktaMvcOptions
{
    OktaDomain = "https://de6.oktaprew.com",
    ClientId = "0oh7",
    ClientSecret = "h70sBO73A1UIt",
    Scope = new List<string> { "openid", "profile", "email" }
});

app.UseAuthentication();
=============================================================================
[HttpPost("[action]")]
        public IActionResult Index()
        {
            var msgChkOktaUser = new StringBuilder(1000);
            var xmlDoc = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            if (!string.IsNullOrEmpty(Request.Form["SAMLResponse"]))
            {
                var samlResponses = Request.Form["SAMLResponse"];
                // the sample data sent us may be already encoded, 
                // which results in double encoding
                
                var realayState = Request.Form["RelayState"];
                if (!string.IsNullOrEmpty(samlResponses) && samlResponses.Count > 0)
                {
                    var samlXmlstr = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponses));
                    xmlDoc.LoadXml(samlXmlstr);
                }

            }

            return Content("Test");
        }
  
=============================================================
upgraded users:
https://developer.okta.com/pricing/
https://www.okta.com/free-trial/
https://www.okta.com/integrate/signup/

https://developer.okta.com/docs/guides/implement-auth-code/use-flow/
https://github.com/okta/samples-aspnetcore/blob/master/okta-hosted-login/okta-aspnetcore-mvc-example/Startup.cs
https://developer.okta.com/blog/2017/06/29/oidc-user-auth-aspnet-core
https://developer.okta.com/okta-sdk-dotnet/latest/api/Okta.Sdk.User.html
https://github.com/okta/samples-aspnetcore
https://developer.okta.com/blog/2018/02/01/secure-aspnetcore-webapi-token-auth

https://csharp.hotexamples.com/examples/-/AuthnRequest/-/php-authnrequest-class-examples.html
https://www.codeproject.com/Articles/56640/Performing-a-SAML-Post-with-C
https://github.com/i8beef/SAML2

========================================================
  public HttpResponseMessage Login()
        {
            List<string> cacheDataKeys;
            string cacheData;
            string errorMsg;
            CacheDataHelper.CheckFileCache("key_getperson", @"E:\Projects\2019\SatafApi\SatafApi\Config\CacheMapping.xml", out cacheDataKeys, out errorMsg);
            if(string.IsNullOrEmpty(errorMsg) && cacheDataKeys !=null && cacheDataKeys.Count > 0)
            {
                CacheDataHelper.CheckDbCache(cacheDataKeys, out cacheData, out errorMsg);
                if (string.IsNullOrEmpty(errorMsg))
                {
                    //var exObj = JsonConvert.DeserializeObject<ExpandoObject>("{\"a\":1}") as dynamic;

                    //Console.WriteLine($"exObj.a = {exObj?.a}, type of {exObj?.a.GetType()}");
                    var exObj = JsonConvert.DeserializeObject<ExpandoObject>(cacheData as dynamic);
                    var x= exObj?.Gender;
                    var test=JsonConvert.DeserializeObject<RootObject>(cacheData);
                }
            }
        }
============================================================================
  using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;

namespace SatafApi.Helper
{
    public static class CacheDataHelper
    {
        public static void CheckFileCache(string operation, string datasettingsfilepath, out List<string> cachevalue, out string errormsg)
        {
            Dictionary<string, List<string>> cacheData=null;
            cachevalue = null;
            errormsg = string.Empty;
            try
            {
                cacheData = MemoryCacher.getValue<Dictionary<string, List<string>>>("CrmProcs");
                if (cacheData == null)
                {
                    cacheData = XmlSettings(datasettingsfilepath);
                    MemoryCacher.setValue("CrmProcs", cacheData);
                }
                if (cacheData != null)
                {
                    cacheData.TryGetValue(operation, out cachevalue);
                }
            }
            catch(Exception ex)
            {
                errormsg = ex.Message;
            }
            
        }

        public static void CheckDbCache(List<string> keynames, out string cacheData, out string errormsg)
        {
            Dictionary<string, string> cacheDict = null;
            errormsg = string.Empty;
            cacheData = string.Empty;
            try
            {
                cacheDict = MemoryCacher.getValue<Dictionary<string, string>>("HbDbCache");
                if (cacheDict == null)
                {
                    cacheDict = getCacheDataFromDb();
                    MemoryCacher.setValue("HbDbCache", cacheDict);
                }
                if (cacheDict != null)
                {
                    StringBuilder sb = new StringBuilder();
                    sb.Append("{");
                    bool first = true;
                    foreach (var key in keynames)
                    {
                        if (!first)
                        {
                            sb.Append(",");
                        }
                        sb.AppendFormat("\"{0}\":{1}", key, cacheDict[key]);
                        first = false;
                    }
                    sb.Append("}");
                    cacheData = sb.ToString();
                }
            }
            catch (Exception ex)
            {
                errormsg = ex.Message;
            }

        }

        private static Dictionary<string, List<string>> XmlSettings(string _dataSettingsFilePath)
        {
            XDocument xdoc = XDocument.Load(_dataSettingsFilePath);
            var elist = xdoc.Descendants("Cache").Select(e => new { Key = e.Attribute("Operation").Value, ValueCol = e.Attribute("ValueCollection").Value})
                        .ToDictionary(t => t.Key, t => t.ValueCol.Split(',').ToList());
            return elist;
        }

        private static Dictionary<string,string> getCacheDataFromDb()
        {
            Dictionary<string, string> cacheData = new Dictionary<string, string>();
            List<TestModel> list = new List<TestModel>();
            list.Add(new TestModel { Data = "Mr.",Value="1",DisplayOrder="1" });
            list.Add(new TestModel { Data = "Mrs.", Value = "2", DisplayOrder = "2" });
            cacheData.Add("FirstName", JsonConvert.SerializeObject(list, Newtonsoft.Json.Formatting.None));

            List<TestModel> list1 = new List<TestModel>();
            list1.Add(new TestModel { Data = "Male", Value = "1", DisplayOrder = "1" });
            list1.Add(new TestModel { Data = "Female", Value = "2", DisplayOrder = "2" });
            cacheData.Add("Gender", JsonConvert.SerializeObject(list1, Newtonsoft.Json.Formatting.None));
            return cacheData;
        }
    }

    public class TestModel
    {
        public string Value { get; set; }
        public string Data { get; set; }
        public string DisplayOrder { get; set; }
    }

    public class RootObject
    {
        public List<TestModel> FirstName { get; set; }
        public List<TestModel> Gender { get; set; }
    }
}

======================================================================
  https://www.newtonsoft.com/json/help/html/QueryJsonDynamic.htm
https://www.red-gate.com/simple-talk/dotnet/c-programming/working-with-the-dynamic-type-in-c/
