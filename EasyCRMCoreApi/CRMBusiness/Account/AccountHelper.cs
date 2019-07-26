using CRMBusiness.Interfaces;
using CRMBusiness.Models;
using CRMDal.Account;
using CRMDal.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace CRMBusiness.Account
{
    public class AccountHelper : IAccountHelper
    {
        private IAccountData _accountData;

        public AccountHelper(IAccountData accountData)
        {
            _accountData = accountData;
        }
        public CrmResponse<AccountUserModel> AccountLogin(AccountLoginModel accountModel)
        {
            string _errormsg;
            CrmResponse<AccountUserModel> _response = new CrmResponse<AccountUserModel>();
            var data = _accountData.AccountLoginData(accountModel.UserName, accountModel.Password, out _errormsg);
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
                _response.Data = new AccountUserModel { FullName = data.Tables[0].Rows[0].ItemArray[0].ToString()+ data.Tables[0].Rows[0].ItemArray[1].ToString(), Email = "", Token = "avb5t-6tyui-re34d" };
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
    }
}
