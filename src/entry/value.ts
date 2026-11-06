import { announce } from '../capture.ts';
import { holdOutOfCache } from '../dom.ts';
import { bootValue } from '../value.ts';

holdOutOfCache();
void bootValue();
void announce();
