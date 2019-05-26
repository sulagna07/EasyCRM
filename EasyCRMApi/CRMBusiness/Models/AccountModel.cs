using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CRMBusiness.Models
{
    public class AccountLoginModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    public class AccountRegisterModel
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string RePassword { get; set; }
        public bool TermsAgree { get; set; }

    }

    public class AccountUserModel
    {
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }

    }
}
