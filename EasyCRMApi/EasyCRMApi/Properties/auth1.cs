Configuration = configuration;
            var contentRoot = configuration.GetValue<string>(WebHostDefaults.ContentRootKey);
            
            var dom = new ConfigurationBuilder()
                        .AddJsonFile(contentRoot+@"\Configs\BrandMapping.json", optional: true, reloadOnChange: true);
            configuration.Bind(dom);
            //Configuration = dom.Build(dom);
            var t = Configuration["AuthConfig:SecretKey"];
			
			
			public Startup(IConfiguration configuration, IHostingEnvironment env)
{
     var contentRoot = env.ContentRootPath;
}
			
			
Host.CreateDefaultBuilder(args).ConfigureAppConfiguration((hostingContext, config) =>
            {
                var ctx=hostingContext.Configuration;
                //config.AddJsonFile(, optional: true, reloadOnChange: true);
            })
						
	Microsoft.AspNet.WebApi.Client		
================================================================
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using RtmValueObject;
using System;

namespace SGAuthFilter.SGFilter
{
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
                        var loginModel = requsetmodel as RtmRequest<dynamic>;
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
======================================================================================
	[HttpPost("[Action]")]
	[AllowAnonymous]
	[ServiceFilter(typeof(SGBrandFilter))]
	public async Task<IActionResult> UserLogin(RtmRequest<dynamic> rtmRequest)
	{
		var cn = HttpContext;
		var data = await _apiClient.PostAsync<RtmsResp<dynamic>, RtmRequest<dynamic>>("weatherforecast/getlookupdata", rtmRequest);

		return Ok(data);
	}
===================================================================================

public async Task<T> PostAsync<T>(string requesturl)
{
	return await PostAsync<T,string>(requestUrl, string.Empty);
}
 
public async Task<T1> PostAsync<T1,T2>(string requesturl, T2 content)
{
	addHeaders();
	var response = await _httpClient.PostAsync(requestUrl, CreateHttpContent(content));
	response.EnsureSuccessStatusCode();
	return await response.Content.ReadAsAsync<T1>();
}
===================================================================================
public dynamic SelectWorker(RtmRequest<dynamic> req)
{
	using (var scope = _provider.CreateScope())
	{
		var scopedProcessingService =
			scope.ServiceProvider
				.GetRequiredService(_workerList1["1"]);
		var dlgate = Delegate.CreateDelegate(typeof(ExecuteOperationDelegate<RtmRequest<dynamic>>), scopedProcessingService, "ExecuteOperation");
		return dlgate.DynamicInvoke(req);
	}
}
====================================================================================
public RtmsResp<dynamic> ExecuteOperation(RtmRequest<dynamic> rtmRequest)
{
	return _dalHelper.GetLookUp(rtmRequest);
}
=======================================================================================
public RtmsResp<dynamic> GetLookUp(RtmRequest<dynamic> req)
{
	RtmsResp<dynamic> resp = new RtmsResp<dynamic>();
	string validationMsg;
	var sqlParams = new SqlParameter[1];
	sqlParams[0] = new SqlParameter() {
		ParameterName = "@JsonReq",
		SqlDbType=SqlDbType.NVarChar,
		Direction = ParameterDirection.Input,
		Value= JsonSerializer.Serialize(req)
	};
	resp.Data=_iSqlHelper.ExecuteScalar("test",CommandType.StoredProcedure, "CricInfoTest_iu", out validationMsg, sqlParams);
	
	return resp;
}
======================================================================================
public object ExecuteScalar(string connectionString, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
{
	if (connectionString == null || connectionString.Length == 0) throw new ArgumentNullException("connectionString");

	using (DbConnection connection = _factory.CreateConnection())
	{
		connection.ConnectionString = "Data Source=.\\SQLEXPRESS;Initial Catalog=CricInfo;Integrated Secu";
		connection.Open();
		return ExecuteScalar(connection, commandType, commandText, out _errormsg, commandParameters);
	}
}

private object ExecuteScalar(DbConnection connection, CommandType commandType, string commandText, out string _errormsg, params SqlParameter[] commandParameters)
{
	if (connection == null) throw new ArgumentNullException("connection");

	// Create a command and prepare it for execution

	using (DbCommand cmd = connection.CreateCommand())
	{
		PrepareCommand(cmd, commandType, commandText, commandParameters);
		var dbReader = cmd.ExecuteScalar();
		_errormsg = DBException(cmd);
		return dbReader;
	}          
}
==========================================================================================
