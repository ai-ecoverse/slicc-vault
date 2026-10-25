import { announce } from '../capture.ts';
import { holdOutOfCache } from '../dom.ts';
import { boot } from '../frame.ts';

holdOutOfCache();
void boot();
void announce();
