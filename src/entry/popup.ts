import { announce } from '../capture.ts';
import { reloadOnRestore } from '../dom.ts';
import { bootPopup } from '../popup.ts';

reloadOnRestore();
void bootPopup();
void announce();
