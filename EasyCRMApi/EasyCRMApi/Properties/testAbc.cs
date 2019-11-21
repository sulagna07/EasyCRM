[HttpPost("[Action]")]
[AllowAnonymous]
[ServiceFilter(typeof(XSRFCookieFilter))]
[ServiceFilter(typeof(SGBrandFilter))]
public async Task<IActionResult> UserLogin(MyRtmLoginRequest<dynamic> rtmRequest)
{
	var cn = HttpContext;
	rtmRequest.IsChacheRequired = _cacheHelper.CachePopulationRequired();
	var data = await _apiClient.PostAsync<MyRtmResponse<dynamic>, MyRtmLoginRequest<dynamic>>("weatherforecast/GetLoginData", rtmRequest);
	if (data.Success)
	{
		var authToken = _authService.CreateToken(CommonService.DeserializeString<UserClaimModel>(data.Data));
		Response.Headers.Add("Auth-Token", authToken);
		return Ok(data);
	}
	return NotFound(data);
}
<PackageReference Include="Microsoft.AspNet.WebApi.Client" Version="5.2.7" />
===============================================================
[HttpPost("[action]")]
public IActionResult GetLoginData(MyRtmLoginRequest<dynamic> rtmRequest)
{
	var resp = _workMonitor.SelectWorker(new MyRtmRequest<dynamic> { Data = rtmRequest.Data, Operation = rtmRequest.Operation, UserData = rtmRequest.UserData }) as MyRtmResponse<dynamic>;
	if (rtmRequest.IsChacheRequired && resp.Success)
	{
		var cacheresp= _workMonitor.SelectWorker(new MyRtmRequest<dynamic> { Operation = "PopulateCacheData"}) as MyRtmResponse<dynamic>;
		if (cacheresp.Success)
		{
			resp.CacheData = cacheresp.Data;
		}
		else
		{
			resp.Data = null;
			resp.Success = false;
			resp.ErrorMessage = cacheresp.ErrorMessage;
		}
	}
	return Ok(resp);
}
===============================================================
public class MyRtmRequest<T>
    {
        public T Data { get; set; }
        public string Operation { get; set; }
        public RtmUserData UserData { get; set; }
    }

    public class MyRtmResponse<T>
    {
        public T Data { get; set; }
        public bool Success { get; set; }
        public string ErrorMessage { get; set; }
        public dynamic CacheData { get; set; }
    }

    public class MyRtmLoginRequest<T> : MyRtmRequest<T>
    {
        public bool IsChacheRequired { get; set; }
    }

    public class RtmUserData
    {
        public string UserName { get; set; }
        public string RoleId { get; set; }
        public string Brand { get; set; }
        public string RequestIP { get; set; }
    }
===================================================================
public MyRtmResponse<dynamic> GetLookUp(MyRtmRequest<dynamic> req)
{
	MyRtmResponse<dynamic> resp;
	try
	{
		var sqlParams = new SqlParameter[1];
		sqlParams[0] = new SqlParameter()
		{
			ParameterName = "@JsonReq",
			SqlDbType = SqlDbType.NVarChar,
			Direction = ParameterDirection.Input,
			Value = JsonSerializer.Serialize(req)
		};
		var jsonresponse = _iSqlHelper.ExecuteScalar("test", CommandType.StoredProcedure, "CricInfoTest_iu", out string validationMsg, sqlParams);
		resp=new MyRtmResponse<dynamic>();
		if (string.IsNullOrEmpty(validationMsg))
		{
			resp.Data = jsonresponse;
			resp.Success = true;
		}
		else
		{
			resp.ErrorMessage = validationMsg;
			resp.Success = false;
		}
	}
	catch(SqlException ex)
	{
		resp = new MyRtmResponse<dynamic>();
		resp.Success = false;
		resp.ErrorMessage = ex.Message;
	}
	catch(Exception ex)
	{
		resp = new MyRtmResponse<dynamic>();
		resp.Success = false;
		resp.ErrorMessage = ex.Message;
	}
	return resp;
}
		
=============================================================================	
