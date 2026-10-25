import { bootButton } from '../button.ts';
import { announce } from '../capture.ts';
import { holdOutOfCache } from '../dom.ts';

holdOutOfCache();
void bootButton();
void announce();
