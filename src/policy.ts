import type { ExecMode, ExitName, ExitPolicyView, Rule } from './contract.ts';

export interface Policy {
  rules(name: string): Rule[];
  exec(name: string): ExecMode;
  argv(name: string): string[][] | null;
  exits(name: string): ExitName[] | null;
  view(): ExitPolicyView;
}

export const EMPTY: Policy = {
  rules: () => [],
  exec: () => false,
  argv: () => null,
  exits: () => null,
  view: () => ({ file: '/etc/slicc/secrets-policy.toml', sha256: null, restricted: [] }),
};
