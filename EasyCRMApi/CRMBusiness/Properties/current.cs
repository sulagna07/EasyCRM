Angular:

export class FetchDataComponent{

  public forecasts: WeatherForecast[];
  isAuthenticated: boolean;

  constructor(http: HttpClient, @Inject('BASE_URL') baseUrl: string) {
    //let headers = new HttpHeaders({ 'Content-Type': 'application/json' });, { headers: headers }
    const requestbody: LohaRequest = {
      businessData: '',
      operation: "key_getforecast"
    };
    http.post<LohaResponse>(baseUrl + 'api/LohaApi/CommonExecutor', requestbody).subscribe(result => {
      console.log(result);
      this.forecasts = result.data;
    }, error => console.error(error));
  }
  
}

interface LohaResponse {
  Success: boolean;
  Data: any;
  Message: string;
}

interface Person {
  Name: string;
  Age: number;
  Address: string
}

interface LohaRequest {
  BusinessData: any;
  Operation: string;
}

=====================================================
[Route("api/[controller]")]
[ApiController]
[Authorize]
public class LohaApiController : ControllerBase
{
	private IApiClient _client;
	public LohaApiController(IApiClient client)
	{
		_client = client;
	}
	[HttpPost("[action]")]
	public async Task<object> CommonExecutor([FromBody]LohaRequest request)
	{
		try
		{
			var msg = await _client.PostAsync("commonapi/commonexecuter", request);
			return JsonConvert.DeserializeObject(msg);
		}
		catch (Exception ex)
		{
			LohaResponse<string> resp = new LohaResponse<string>();
			resp.Success = false;
			resp.Message = ex.Message;
			resp.Data = string.Empty;
			return JsonConvert.SerializeObject(resp, new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() });
		}

	}
}

/// <summary>  
/// Common method for making POST calls  
/// </summary>  
public async Task<string> PostAsync<T>(string requestUrl, T content)
        {
            addHeaders();
            var response = await _httpClient.PostAsJsonAsync(requestUrl, content);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
===================================================
using LohaWorker;
using Microsoft.AspNetCore.Mvc;
using ValueObjects;

namespace LohaApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommonApiController : ControllerBase
    {
        IWorkMonitor _workmonitor;
        public CommonApiController(IWorkMonitor workmonitor)
        {
            _workmonitor = workmonitor;
        }

        [HttpPost("[action]")]
        public object CommonExecuter(LohaRequest lohaRequest)
        {
           var rtobj=_workmonitor.SelectWorker(lohaRequest);
           return rtobj;
        }

        [HttpPost("[action]")]
        public string CommonFormExecuter(LohaFormRequest req)//[Bind("Operation")]Product product,List<IFormFile> AvImage
        {
            object rtobj=null;
            if (Request.HasFormContentType)
            {
                var form = Request.Form;
                rtobj = _workmonitor.SelectWorker(form["operation"], form["data"], form.Files.GetEnumerator());
            }
            return rtobj == null ? string.Empty : (string)rtobj;
        }
    }
}
==================================================================
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using ValueObjects;

namespace LohaWorker
{
    public class WorkMonitor : IWorkMonitor {
        private readonly IServiceProvider _provider;
        private readonly IMemoryCache _memoryCache;
        private readonly IConfiguration _config;
        private delegate T ExecuteOperation<T>(T x,T y);
        private delegate T1 ExecuteOperation<T1,T2>(T1 x, T1 y, T2 z);
        public WorkMonitor(IServiceProvider provider, IMemoryCache memoryCache, IConfiguration config)
        {
            _provider = provider;
            _memoryCache = memoryCache;
            _config = config;
        }
        public object SelectWorker(LohaRequest request)
        {
            string _procName, _workerName, _actionName;
            CheckCache(request.Operation, _config.GetSection("ExternalPath:XmlSettings").Value, out _procName,out _workerName,out _actionName);
            var d = Delegate.CreateDelegate(typeof(ExecuteOperation<string>), GetInstance(_workerName), _actionName);
            return d.DynamicInvoke(request.BusinessData, _procName);
        }
        public string SelectWorker(string Operation, string BusinessData, IEnumerator<IFormFile> files)
        {
            object ob = null;
            string _procName, _workerName, _actionName;
            CheckCache(Operation, _config.GetSection("ExternalPath:XmlSettings").Value, out _procName, out _workerName, out _actionName);
            var d = Delegate.CreateDelegate(typeof(ExecuteOperation<string, IEnumerator<IFormFile>>), GetInstance(_workerName), _actionName);
            ob = d.DynamicInvoke(BusinessData, _procName, files);
            return ob.ToString();
        }

        private object GetInstance(string strtype)
        {
            var type = Type.GetType("LohaWorker." + strtype);
            return ActivatorUtilities.CreateInstance(_provider, type);
        }

        private void CheckCache(string spKey, string _dataSettingsFilePath,out string _procName, out string _workerName, out string _actionName)
        {
            LohaWorkMonitor procName=null;
            Dictionary<string, LohaWorkMonitor> procNames;
            bool isExist = _memoryCache.TryGetValue("CrmProcs", out procNames);
            if (!isExist)
            {
                procNames = XmlSettings(_dataSettingsFilePath);
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetPriority(CacheItemPriority.NeverRemove);

                _memoryCache.Set("CrmProcs", procNames, cacheEntryOptions);
            }
            if (procNames != null)
            {
                procNames.TryGetValue(spKey, out procName);
                
            }
            if(procName != null)
            {
                _procName = procName.ProcName;
                _workerName = procName.WorkerName;
                _actionName = procName.ActionName;
            }
            else
            {
                _procName = string.Empty;
                _workerName = string.Empty;
                _actionName = string.Empty;
            }

        }

        private Dictionary<string, LohaWorkMonitor> XmlSettings(string _dataSettingsFilePath)
        {
            XmlDocument xml = new XmlDocument();
            xml.Load(_dataSettingsFilePath);
            XDocument xdoc = XDocument.Load(_dataSettingsFilePath);
            var elist = xdoc.Descendants("Proc").Select(e => new { Key = e.Attribute("SpKey").Value, ProcName = e.Attribute("SpName").Value, WorkerName = e.Attribute("Worker").Value, ActionName = e.Attribute("Action").Value })
                        .ToDictionary(t => t.Key, t => new LohaWorkMonitor { ProcName=t.ProcName,WorkerName=t.WorkerName, ActionName = t.ActionName});
            return elist;
        }
    }
}


=========================================================================
namespace LohaWorker
{
    public class HomeWorker
    {
        IHomeBusiness _homeBusiness;
        public HomeWorker(IHomeBusiness homeBusiness)
        {
            _homeBusiness = homeBusiness;
        }
        public string GetEmpName(string data, string procname)
        {
            return JsonConvert.SerializeObject(_homeBusiness.GetName(data,procname), new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() });
        }

        public string GetForeCast(string data, string procname)
        {
            return JsonConvert.SerializeObject(_homeBusiness.GetForecast(data,procname), new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() });
        }

        public string GetForeCastForm(string data, string procname, IEnumerator<IFormFile> files)
        {
            return "He Ha";
        }
    }
}
=============================================================================
namespace LohaBusiness
{
    public class HomeBusiness: IHomeBusiness
    {
        IHomeData _homeData;
        public HomeBusiness(IHomeData homeData)
        {
            _homeData = homeData;
        }
        public LohaResponse<Person> GetName(string businessData,string procName)
        {
            LohaResponse<Person> lresp = new LohaResponse<Person>();
            try
            {
                Person per = JsonConvert.DeserializeObject<Person>(businessData);
                lresp.Data = _homeData.GetEmpName(per.Age);
                lresp.Success = true;
            }
            catch(Exception ex)
            {
                lresp.Success = false;
                lresp.Message = ex.Message;
            }
            return lresp;
        }

        public LohaResponse<IEnumerable<WeatherForecast>> GetForecast(string businessData,string procName)
        {
            LohaResponse<IEnumerable<WeatherForecast>> lresp = new LohaResponse<IEnumerable<WeatherForecast>>();
            try
            {
                lresp.Data = _homeData.GetForeCast();
                lresp.Success = true;
            }
            catch (Exception ex)
            {
                lresp.Success = false;
                lresp.Message = ex.Message;
            }
            return lresp;
        }

       /* public LohaResponse<Person> SaveFormData(string businessData, string procName, string, IEnumerator<IFormFile> files, File filesx)
        {
            LohaResponse<Person> lresp = new LohaResponse<Person>();

        }*/
    }
}

======================================================================================
public class LohaResponse<T>
    {
        public bool Success { get; set; }
        public T Data { get; set; }
        public string Message { get; set; }
    }

public class LohaRequest
{
	public string Operation { get; set; }
	public string BusinessData { get; set; }
}

========================================================================================
public void ConfigureServices(IServiceCollection services)
        {
            var authority = Configuration["OktaConfig:Issuer"];

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            authority + Configuration["OktaConfig:OpenidEndpoint"],
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever());
            
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
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
            });
        }
===============================================================================
"OktaConfig": {
    "Issuer": "https://dev-345075.okta.com/oauth2/default",
    "OpenidEndpoint": "/.well-known/openid-configuration"
  } 
===============================================================================
app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSpaStaticFiles();
            app.UseAuthentication();
================================================================
import { Injectable } from '@angular/core';
import {HttpEvent,HttpHandler,HttpInterceptor,HttpRequest} from '@angular/common/http';
import { Observable } from 'rxjs';
import { from } from 'rxjs';
import { OktaAuthService } from '@okta/okta-angular';

@Injectable({
  providedIn: 'root'
})
export class AuthInterceptor implements HttpInterceptor {
  constructor(private oktaAuth: OktaAuthService) { }

  intercept(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    return from(this.handleAccess(request, next));//Observable.fromPromise(this.handleAccess(request, next));
  }

  private async handleAccess(
    request: HttpRequest<any>,
    next: HttpHandler
  ): Promise<HttpEvent<any>> {
    const accessToken = await this.oktaAuth.getAccessToken();
    request = request.clone({
      setHeaders: {
        Authorization: 'Bearer ' + accessToken
      }
    });
    return next.handle(request).toPromise();
  }
}
================================================================================
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthInterceptor } from './shared/auth.interceptor';
========================================================================
providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }
  ],
==========================================================================
export class HomeComponent implements OnInit {
  isAuthenticated: boolean;

  constructor(private oktaAuth: OktaAuthService) {
    console.log("Constructor-1");
  }

  async ngOnInit(){
    console.log("Ngonit-2");
    this.isAuthenticated = await this.oktaAuth.isAuthenticated();
    // Subscribe to authentication state changes
    this.oktaAuth.$authenticationState.subscribe(
      (isAuthenticated: boolean) => (this.isAuthenticated = isAuthenticated)
    );
  }
}
======================================================================
<div>
  <div>
    <button *ngIf="!isAuthenticated"
            (click)="oktaAuth.loginRedirect()">
      Login
    </button>
    <button *ngIf="isAuthenticated"
            [routerLink]="['/fetch-data']">
      Sugar Level List
    </button>
    <button *ngIf="isAuthenticated"
            (click)="oktaAuth.logout()">
      Login
    </button>
  </div>
</div>
=================================
https://developer.okta.com/blog/2018/07/27/build-crud-app-in-aspnet-framework-webapi-and-angular  
