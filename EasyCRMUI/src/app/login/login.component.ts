import { Component, OnInit } from '@angular/core';
import { Router,ActivatedRoute } from '@angular/router';
import { FormGroup, FormControl, Validators, FormBuilder } from '@angular/forms';
import {AccountLogin} from '../models/account-login';
import {AccountService} from '../services/account.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  returnUrl: string;
  constructor(private formbulider: FormBuilder, private accountService : AccountService, 
    private router: Router,private route: ActivatedRoute,) { 
    // redirect to home if already logged in
    if (this.accountService.currentUserValue) { 
      this.router.navigate(['/']);
  }
  }

  ngOnInit() {
    this.loginForm = this.formbulider.group({  
      UserName: ['', [Validators.required]],  
      Password: ['', [Validators.required]] 
    });
  }

  onAccountLogin(){
    const loginInfo = this.loginForm.value;
    this.accountService.AccountLogin(loginInfo).subscribe(  
      data => { 
        this.router.navigate(['/']);
      }  
    );
  }

}
