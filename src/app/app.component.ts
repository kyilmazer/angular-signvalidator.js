import { Component } from '@angular/core';
//declare const myFunction: any;
import {signValidator} from '../assets/js/custom.js';

@Component({
  selector: 'my-app',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {

  test() {
    signValidator();
  }
}
