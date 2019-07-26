using CRMBusiness.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace CRMBusiness.Interfaces
{
    public interface IAccountHelper
    {
        CrmResponse<AccountUserModel> AccountLogin(AccountLoginModel accountModel);
        CrmResponse<String> AccountRegister(AccountRegisterModel registerModel);
    }
}
