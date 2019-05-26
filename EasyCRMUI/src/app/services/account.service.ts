import { Injectable } from '@angular/core';
import { HttpClient,HttpHeaders } from '@angular/common/http'; 
import { BehaviorSubject, Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import {CRMResponse,AccountLogin,AccountRegister,AccountUser} from '../models/account-login'

@Injectable({
  providedIn: 'root'
})
export class AccountService {
  url = 'http://localhost/easyapi';
  private currentUserSubject: BehaviorSubject<AccountUser>;
  public currentUser: Observable<AccountUser>;

  constructor(private http: HttpClient) { 
    this.currentUserSubject = new BehaviorSubject<AccountUser>(JSON.parse(localStorage.getItem('currentUser')));
    this.currentUser = this.currentUserSubject.asObservable();
  }

  public get currentUserValue(): AccountUser {
    return this.currentUserSubject.value;
  }

  AccountLogin(accountLoginModel: AccountLogin): Observable<CRMResponse> { 
    console.log(accountLoginModel); 
    const httpOptions = { headers: new HttpHeaders({ 'Content-Type': 'application/json'}) };  
    return this.http.post<CRMResponse>(this.url + '/crmapi/account/login',  
    accountLoginModel, httpOptions).pipe(map(resp => {
      // login successful if there's a jwt token in the response
      if (resp.Success) {
          localStorage.setItem('currentUser', JSON.stringify(resp.Data));
          this.currentUserSubject.next(resp.Data);
      }
      return resp;
    }));  
  }

  AccountRegister(accountRegisterModel: AccountRegister): Observable<CRMResponse> { 
    console.log(accountRegisterModel); 
    const httpOptions = { headers: new HttpHeaders({ 'Content-Type': 'application/json'}) };  
    return this.http.post<CRMResponse>(this.url + '/crmapi/account/register',
    accountRegisterModel,httpOptions);
  }

  logout() {
    // remove user from local storage to log user out
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
  }
}
