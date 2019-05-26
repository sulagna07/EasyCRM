using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using CRMBusiness.Models;
using CRMBusiness.Account;

namespace EasyCRMApi.Controllers
{
    [RoutePrefix("crmapi/account")]
    public class AccountController : ApiController
    {
        [Route("login")]
        [HttpPost]
        public CrmResponse<AccountUserModel> AccountLogin(AccountLoginModel loginModel)
        {
            return new AccountHelper().AccountLogin(loginModel);
        }

        [Route("register")]
        [HttpPost]
        public CrmResponse<String> AccountRegister(AccountRegisterModel registerModel)
        {
            return new AccountHelper().AccountRegister(registerModel);
        }

    }
}
