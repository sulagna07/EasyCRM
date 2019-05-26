import { Component, OnInit } from '@angular/core';
import { FormGroup, FormControl, Validators, FormBuilder } from '@angular/forms';
import {AccountLogin} from '../models/account-login'
import {AccountService} from '../services/account.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {

  registerForm: FormGroup;
  constructor(private formbulider: FormBuilder, private accountService : AccountService) { }

  ngOnInit() {
    this.registerForm = this.formbulider.group({  
      FullName: ['', [Validators.required]],  
      Email: ['', [Validators.required]],
      Password: ['', [Validators.required]],
      RePassword: ['', [Validators.required]],
      TermsAgree: [false, [Validators.required]]  
    });
  }

  onAccountRegister(){
    const registerInfo = this.registerForm.value;
    this.accountService.AccountRegister(registerInfo).subscribe(  
      data => { 
        console.log(data.Data);
      }  
    );
  }

}
