using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CRMBusiness.Models;
using CRMDal.Account;

namespace CRMBusiness.Account
{
    public class AccountHelper
    {
        private AccountData _accountData;

        public AccountHelper()
        {
            _accountData = new AccountData();
        }
        public CrmResponse<AccountUserModel> AccountLogin(AccountLoginModel accountModel)
        {
            string _errormsg;
            CrmResponse<AccountUserModel> _response = new CrmResponse<AccountUserModel>();
            var data=_accountData.AccountLoginData(accountModel.UserName, accountModel.Password, out _errormsg);
            if (!_errormsg.Equals(""))
            {
                _response.Message = _errormsg;
                _response.Success = false;
                _response.Data = null;
            }
            else
            {
                _response.Message = "";
                _response.Success = true;
                _response.Data = new AccountUserModel { FullName=data,Email="",Token="avb5t-6tyui-re34d"};
            }
            return _response;
        }
        public CrmResponse<String> AccountRegister(AccountRegisterModel registerModel)
        {
            string _errormsg;
            CrmResponse<String> _response = new CrmResponse<string>();
            if (registerModel.Password.Equals(registerModel.RePassword))
            {
                var data = _accountData.AccountRegisterData(registerModel.FullName, registerModel.Email, registerModel.Password, out _errormsg);
                if (!_errormsg.Equals(""))
                {
                    _response.Message = _errormsg;
                    _response.Success = false;
                    _response.Data = null;
                }
                else
                {
                    _response.Message = "";
                    _response.Success = true;
                    _response.Data = data;
                }
            }
            else
            {
                _response.Message = "Password did not match";
                _response.Success = false;
                _response.Data = null;
            }
            
            return _response;
        }

        public CrmResponse<String> LoadUser(string uname)
        {
            //string _errormsg;
            CrmResponse<String> _response = new CrmResponse<String>();
            _response.Message = "";
            _response.Success = true;
            _response.Data = "Jhon";

            return _response;
        }
    }
}
