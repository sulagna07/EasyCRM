[HttpPost("[Action]")]
[AllowAnonymous]
//[ServiceFilter(typeof(XSRFCookieFilter))]
//[ServiceFilter(typeof(SGBrandFilter))]
public async Task<IActionResult> UserLogin(MyRtmLoginRequest<dynamic> rtmRequest)
{
	var data = await _apiClient.PostAsync<MyRtmResponse<BusinessData<dynamic>>, MyRtmLoginRequest<dynamic>>("weatherforecast/GetLoginData", rtmRequest);//MyRtmResponse<dynamic>
	if (data.Success)
	{
		var clm = data.BusinessData.Data as UserClaimModel;
		var authToken = _authService.CreateToken(clm);
		Response.Headers.Add("Auth-Token", authToken);
		return Ok(data);
	}
	return NotFound(data);
}

==================================================================
public async Task<T1> PostAsync<T1,T2>(string requestUrl, T2 content)
{
	addHeaders();
	var response = await _httpClient.PostAsync(requestUrl, CreateHttpContent(content));
	response.EnsureSuccessStatusCode();
	var dx=await response.Content.ReadAsStringAsync();
	var options = new JsonSerializerOptions
	{
		PropertyNameCaseInsensitive = true
	};
	return JsonSerializer.Deserialize<T1>(dx, options);
}
=================================================================
[HttpPost("[action]")]
public IActionResult GetLoginData(MyRtmLoginRequest<dynamic> rtmRequest)
{
	MyRtmResponse<dynamic> resp;
	try
	{
		resp = _workMonitor.SelectWorker(new MyRtmRequest<dynamic> { Data = rtmRequest.Data, Operation = rtmRequest.Operation, UserData = rtmRequest.UserData }) as MyRtmResponse<dynamic>;
	}catch (Exception ex)
	{
		if (ex.InnerException != null) ex = ex.InnerException;
		resp = new MyRtmResponse<dynamic>();
		resp.Success = false;
		resp.ExceptionMessage = ex.Message;
	}
	return Ok(resp);
}
====================================================================
public MyRtmResponse<dynamic> GetLookUp(MyRtmRequest<dynamic> req)
{
	MyRtmResponse<dynamic> resp;

	var sqlParams = new SqlParameter[1];
	sqlParams[0] = new SqlParameter()
	{
		ParameterName = "@JsonReq",
		SqlDbType = SqlDbType.NVarChar,
		Direction = ParameterDirection.Input,
		Value = JsonSerializer.Serialize(req)
	};
	var jsonresponse = _iSqlHelper.ExecuteScalar("test", CommandType.StoredProcedure, "CricInfoTest_iu", out string validationMsg, sqlParams);
	resp = new MyRtmResponse<dynamic>();
	BusinessData<dynamic> bData = new BusinessData<dynamic>();
	if (string.IsNullOrEmpty(validationMsg))
	{
		bData.Data = JsonSerializer.Deserialize<dynamic>(jsonresponse.ToString());
		bData.IsValid = true;
	}
	else
	{
		bData.BusinessErrorMessage = validationMsg;
		bData.IsValid = false;
	}
	resp.BusinessData = bData;
	resp.Success = true;
	return resp;
}
=============================================================================
public class MyRtmRequest<T>
{
	public T Data { get; set; }
	public string Operation { get; set; }
	public RtmUserData UserData { get; set; }
}

public class MyRtmResponse<T>
{
	public T BusinessData { get; set; }
	public bool Success { get; set; }
	public string ExceptionMessage { get; set; }
	public dynamic CacheData { get; set; }
}

public class BusinessData<T>
{
	public T Data { get; set; }
	public bool IsValid { get; set; }
	public string BusinessErrorMessage { get; set; }
}
=============================================================================
