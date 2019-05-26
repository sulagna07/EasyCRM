export class AccountLogin {
    UserName:string;
    Password:string;
}
export class CRMResponse{
    Success:boolean;
    Message:string;
    Data:any;
}

export class AccountRegister{
    FullName:string;
    Email:string;
    Password:string;
    RePassword:string;
    TermsAgree:boolean;
}

export class AccountUser{
    FullName:string;
    Email:string;
    Token:string;
}
