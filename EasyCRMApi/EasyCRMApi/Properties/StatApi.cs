using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using System.Web.SessionState;

namespace SatafApi
{
    public class WebApiApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            //GlobalConfiguration.Configure(WebApiConfig.Register);
            WebApiConfig.Register(RouteTable.Routes);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            //RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            
        }

        public override void Init()
        {
            this.PostAuthenticateRequest += Application_PostAuthorizeRequest;
            base.Init();
        }

        protected void Application_PostAuthorizeRequest(object sender, EventArgs e)
        {
            if (IsWebApiRequest())
            {
                HttpContext.Current.SetSessionStateBehavior(SessionStateBehavior.Required);
            }
        }

        private bool IsWebApiRequest()
        {
            return HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath.StartsWith(WebApiConfig.UrlPrefixRelative);
        }
    }
}
=======================================================================================
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Http;
using System.Web.Routing;

namespace SatafApi
{
    public static class WebApiConfig
    {
        public static string UrlPrefix { get { return "api"; } }
        public static string UrlPrefixRelative { get { return "~/api"; } }
        /*public static void Register(HttpConfiguration config)
        {
            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            // Web API configuration and services

            // Web API routes
            config.MapHttpAttributeRoutes();

            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: WebApiConfig.UrlPrefix + "/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }*/
        public static void Register(RouteCollection routes)
        {
            routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: WebApiConfig.UrlPrefix + "/{controller}/{action}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
        }
    }
}
==========================================================================
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;

namespace SatafApi.Controllers
{
    public class LoginController : ApiController
    {
        [HttpGet]
        public HttpResponseMessage Login()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
            HttpContext.Current.Session["Name"] = "B R";
            response.Content = new StringContent("{ \"Result\" : \"OK\", \"Records\":" + "hi" + "\"}");
            return response;
        }

        [HttpGet]
        public HttpResponseMessage LoginName()
        {
            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent(HttpContext.Current.Session["Name"].ToString());
            return response;
        }
    }
}
=========================================================================================
https://stackoverflow.com/questions/9594229/accessing-session-using-asp-net-web-api
https://stackoverflow.com/questions/11478244/asp-net-web-api-session-or-something
https://www.code-sample.com/2017/10/access-session-in-web-api-2-mvc-5.html
https://forums.asp.net/t/2128410.aspx?Web+API+session+managment
https://www.wiliam.com.au/wiliam-blog/enabling-session-state-in-web-api
https://www.codeproject.com/Tips/513522/Providing-session-state-in-ASP-NET-WebAPI