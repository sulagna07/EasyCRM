

===============================================================================================
<?xml version="1.0" encoding="utf-8"?>
<configuration>
<system.webServer>
  <rewrite>
    <rules>
      <rule name="Angular Routes" stopProcessing="true">
        <match url="^satafclient/" />
        <conditions logicalGrouping="MatchAll">
          <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
          <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
        </conditions>
        <action type="Rewrite" url="/satafclient/" />
      </rule>
    </rules>
  </rewrite>
</system.webServer>

</configuration>

==========================================================================================
[HttpPost("[action]")]
        public dynamic TestExecuter(LohaRequest lohaRequest)
        {
            HomeBaseBusinessResponse<TransactionModel> response = new HomeBaseBusinessResponse<TransactionModel>();
            BusinessData<TransactionModel> bsData = new BusinessData<TransactionModel>();

            TransactionModel tran = new TransactionModel();
            tran.Id = "T2345";
            tran.Name = "SBI";
            
            bsData.Data = tran;
            bsData.BusinessErrorMsg = string.Empty;
            bsData.IsValid = true;

            response.Exception = null;
            response.Success = true;
            response.BusinessData = bsData;
            return response;
        }
===================================================================================
[HttpPost("[action]")]
        public async Task<dynamic> TestExecutor([FromBody]LohaRequest request)
        {
            try
            {
                UserData userData = new UserData();
                userData.Name = "Jhon";
                userData.Role = "Admin";
                var msg = await _client.PostAsync("commonapi/TestExecuter", request);//commonexecuter
                var model=JsonConvert.DeserializeObject<HomeBaseBusinessResponse<dynamic>>(msg);
                HomeBaseResponse<dynamic> response = new HomeBaseResponse<dynamic>();
                if (model.Success)
                {
                    response.UserData = userData;
                    response.CacheData = "Test";
                    response.BusinessData = model.BusinessData;
                    response.Success = model.Success;
                }
                else
                {
                    response.Success = false;
                    response.Exception = model.Exception;
                }
                return response;
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
        
=========================================================================================================================
public class BaseResponse
    {
        public bool Success { get; set; }
        public LogError Exception { get; set; }
    }

    public class HomeBaseBusinessResponse<T>: BaseResponse
    {
        public BusinessData<T> BusinessData { get; set; }
    }

    public class HomeBaseResponse<T> : BaseResponse
    {
        public BusinessData<T> BusinessData { get; set; }
        public string CacheData { get; set; }
        public UserData UserData { get; set; }
    }

    public class BusinessData<T>
    {
        public bool IsValid { get; set; }
        public T Data { get; set; }
        public string BusinessErrorMsg { get; set; }
    }

    public class UserData
    {
        public string Name { get; set; }
        public string Role { get; set; }
    }

    public class LogError
    {
        public string Message { get; set; }
        public string ErrorCode { get; set; }
        public ErrorSeverity Severity { get; set; }
    }

    public enum ErrorSeverity{
        High,Medium,Low
    }

    public class TransactionModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }
}
============================================================================================
