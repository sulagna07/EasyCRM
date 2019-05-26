import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ActivatedRoute } from '@angular/router'
import {AccountUser} from '../models/account-login';
import {AccountService} from '../services/account.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit, OnDestroy {
  currentUser: AccountUser;
  currentUserSubscription: Subscription;
  strValue:string;

  constructor(private accountService: AccountService,private route: ActivatedRoute) { 
    this.currentUserSubscription = this.accountService.currentUser.subscribe(user => {
      this.currentUser = user;
    });
  }

  ngOnInit() {
    this.route.params.subscribe(params => {
      this.strValue = params['menu'];
      });
  }

  ngOnDestroy() {
    // unsubscribe to ensure no memory leaks
    this.currentUserSubscription.unsubscribe();
  }

}
