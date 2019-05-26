import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import { ActivatedRoute, ActivationStart, Router, RouterEvent } from '@angular/router';

/*
 *@Injectable({
  providedIn: 'root'
})
 */
//@Injectable()
@Injectable({
  providedIn: 'root'
})
export class RoutingService {

  public isCustomLayout: BehaviorSubject<boolean> = new BehaviorSubject(true);
  private customLayout: boolean;

  constructor(private router: Router) {
    this.init();
  }
  
  /**
   * [init description]
   * @method init
   * @return [description]
   */
  private init() {
    this.router.events.subscribe((event: RouterEvent) => {
      if (event instanceof ActivationStart) {
        this.customLayout = event.snapshot.data.customLayout;
        this.isCustomLayout.next(!!this.customLayout);
      }
    });
  }
}
