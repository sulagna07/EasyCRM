using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CRMBusiness.Account;
using CRMBusiness.Interfaces;
using CRMBusiness.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EasyCRMCoreApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountHelper _accounthelper;
        public AccountController(IAccountHelper accounthelper)
        {
            _accounthelper = accounthelper;
        }
        [HttpPost("login")]
        public CrmResponse<AccountUserModel> AccountLogin(AccountLoginModel loginModel)
        {
            return _accounthelper.AccountLogin(loginModel);
        }

        [HttpPost("register")]
        public CrmResponse<String> AccountRegister(AccountRegisterModel registerModel)
        {
            return _accounthelper.AccountRegister(registerModel);
        }
    }
}