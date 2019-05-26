import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor } from '@angular/common/http';
import { Observable } from 'rxjs';

import { AccountService } from '../services/account.service';

@Injectable()
export class JwtInterceptor implements HttpInterceptor {
    constructor(private accountService: AccountService) {}

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        // add authorization header with jwt token if available
        let currentUser = this.accountService.currentUserValue;
        if (currentUser && currentUser.Token) {
            request = request.clone({
                setHeaders: { 
                    Authorization: `Bearer ${currentUser.Token}`
                }
            });
        }

        return next.handle(request);
    }
}
