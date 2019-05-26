import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AuthGuard } from './guards/auth-guard';

const routes: Routes = [
  
  {
    path: 'login',
    pathMatch: 'full' ,
    loadChildren: './login/login.module#LoginModule',
    data: {
      customLayout:true
    }
  },
  {
    path: '',
    canActivate: [AuthGuard],
    data: {
      title:'Get Started'
    },
    children: [
      {
        path: '',
        component:HomeComponent,
        canActivate: [AuthGuard]
      },
      {
        path: ':menu',
        component:HomeComponent,
        canActivate: [AuthGuard]
      },
      {
        path: 'accordian',
        loadChildren: './login/login.module#LoginModule',
        data: {
          title:'login'
        }
      }
      
    ]
  },
  {
    path: 'register',
    loadChildren: './register/register.module#RegisterModule',
    data: {
      customLayout: true
    }
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
