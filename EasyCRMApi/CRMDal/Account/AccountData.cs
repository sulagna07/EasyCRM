using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CRMDal.Account
{
    public class AccountData
    {
        public string AccountLoginData(string _username, string _password, out string _errormsg)
        {
            var _data ="";
            if (_username.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            {
                if (_password.Equals("test"))
                {
                    _errormsg = "";
                    _data = "Admin";
                }
                else
                {
                    _errormsg = "Incorrect password";
                }
            }
            else
            {
                _errormsg = "Incorrect username";

            }
            return _data;
        }

        public string AccountRegisterData(string _fullname, string _email, string _password, out string _errormsg)
        {
            var _data = "Successfully Registered";
            _errormsg = "";
            /*if (_username.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            {
                if (_password.Equals("test"))
                {
                    _errormsg = "";
                    _data = "Admin";
                }
                else
                {
                    _errormsg = "Incorrect password";
                }
            }
            else
            {
                _errormsg = "Incorrect username";

            }*/
            return _data;
        }
    }
}
