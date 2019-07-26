using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace CRMDal.Interfaces
{
    public interface IAccountData
    {
        DataSet AccountLoginData(string _username, string _password, out string _errormsg);
        string AccountRegisterData(string _fullname, string _email, string _password, out string _errormsg);
    }
}
                                                                                                         