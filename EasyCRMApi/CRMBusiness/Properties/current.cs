Angular:

export class CounterComponent {
  public currentCount = 0;
  public employees: Person;
  
  constructor(http: HttpClient, @Inject('BASE_URL') baseUrl: string) {
    let headers = new HttpHeaders({ 'Content-Type': 'application/json' }); 
    const requestbody: LohaRequest = {
      BusinessData: 1,//"{'Name':'Ajit','Age':'5','Address':'Kolkata'}",
      Operation: "key_getperson"
    };
    console.log(requestbody);
    http.post<LohaResponse>(baseUrl + 'api/SampleData/CommonExecutor', requestbody, { headers: headers }).subscribe(result => {
      console.log(result);
      this.employees = result.Data;
    }, error => console.error(error));
  }

  public incrementCounter() {
    this.currentCount++;
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
[HttpPost("[action]")]
public async Task<string> CommonExecutor([FromBody]LohaRequest request)
{
	try
	{
		var msg = await _client.PostAsync("commonapi/commonexecuter", request);
		return msg;
	}
	catch (Exception ex)
	{
		LohaResponse<string> resp = new LohaResponse<string>();
		resp.Success = false;
		resp.Message = ex.Message;
		resp.Data = string.Empty;
		return JsonConvert.SerializeObject(resp);
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
        public string CommonExecuter(LohaRequest lohaRequest)
        {
           var rtobj=_workmonitor.SelectWorker(lohaRequest);
           return rtobj == null ? string.Empty : (string)rtobj;
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
        public string SelectWorker(LohaRequest request)
        {
            object ob = null;
            string _procName, _workerName, _actionName;
            CheckCache(request.Operation, _config.GetSection("ExternalPath:XmlSettings").Value, out _procName,out _workerName,out _actionName);
            var d = Delegate.CreateDelegate(typeof(ExecuteOperation<string>), GetInstance(_workerName), _actionName);
            ob = d.DynamicInvoke(request.BusinessData, _procName);
            return ob.ToString();
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
using LohaBusiness;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Collections.Generic;

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
            return JsonConvert.SerializeObject(_homeBusiness.GetName(data,procname));
        }

        public string GetForeCast(string data, string procname)
        {
            return JsonConvert.SerializeObject(_homeBusiness.GetForecast(data,procname));
        }

        public string GetForeCastForm(string data, string procname, IEnumerator<IFormFile> files)
        {
            return "He Ha";
        }
    }
}
=============================================================================
using LohaDal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using ValueObjects;

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

