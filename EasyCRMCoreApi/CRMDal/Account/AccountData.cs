using Common;
using CRMDal.Interfaces;
using Microsoft.Extensions.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.IO;
namespace CRMDal.Account
{
    public class AccountData : IAccountData
    {
        //private readonly IConfiguration _config;
        private readonly string _connectionString;
        private readonly IConfigurationRoot _spConfig;
        public AccountData(IConfiguration config)
        {
            //_config = config;
            _connectionString = config.GetConnectionString("EasyCrmCon");
            string spPath = config.GetSection("ExternalPath:SPSettings").Value;

           var builder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile(spPath);
            _spConfig = builder.Build();          
        }

        public DataSet AccountLoginData(string username, string password, out string _errormsg)
        {
            var spName = _spConfig.GetSection("ProcMap:key_getlogininfo").Value;
            SqlParameter[] sqlparams = new SqlParameter[2];
            sqlparams[0] = new SqlParameter("@UserName", username);
            sqlparams[1] = new SqlParameter("@Password", password);
            var loginDs = SqlHelper.ExecuteDataset(_connectionString, CommandType.StoredProcedure, spName, out _errormsg, sqlparams);
            return loginDs;
        }

        public string AccountRegisterData(string _fullname, string _email, string _password, out string _errormsg)
        {
            var _data = "Successfully Registered";
            _errormsg = "";
            return _data;
        }
    }
}
