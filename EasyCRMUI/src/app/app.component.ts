import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { RoutingService } from './services/routing.service';
import { AccountService } from './services/account.service';
import { AccountUser } from './models/account-login';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})

export class AppComponent implements OnInit{
  public customLayout: boolean;
  currentUser: AccountUser;

  constructor(
    private router: Router,
    private accountService: AccountService,
    private routingService: RoutingService
  ) {
    this.accountService.currentUser.subscribe(x => this.currentUser = x);
  }

  ngOnInit() {
    this.routingService.isCustomLayout.subscribe((value: boolean) => {
      this.customLayout = value;
    });
  }

  logout() {
    this.accountService.logout();
    this.router.navigate(['/login']);
  }
}