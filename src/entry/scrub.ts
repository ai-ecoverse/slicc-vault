import { announce } from '../capture.ts';
import { holdOutOfCache } from '../dom.ts';
import { bootScrub } from '../scrub.ts';

holdOutOfCache();
void bootScrub();
void announce();
