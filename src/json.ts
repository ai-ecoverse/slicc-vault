import type { Hit, Scrubber } from '@ai-ecoverse/slicc-scrub';

interface Node {
  out: string;
  parts?: (string | Node)[];
}

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const SPACE = new Set([' ', '\t', '\n', '\r']);
const PUNCTUATION = new Set([...'{}[]:,"', ...SPACE]);
const DEPTH = 256;
const NODES = 200_000;
const SLACK = 1024 * 1024;

function closing(text: string, from: number): number {
  let at = from + 1;
  while (text[at] !== '"') at += text[at] === '\\' ? 2 : 1;
  return at + 1;
}

function over(): never {
  throw new RangeError('the JSON body is too large to scrub by its strings');
}

function tree(text: string, leaf: (token: string) => string): Node {
  const root: Node = { out: '', parts: [] };
  const stack: Node[] = [root];
  let nodes = 0;
  let at = 0;
  while (at < text.length) {
    if (stack.length > DEPTH || nodes > NODES) over();
    const top = stack[stack.length - 1].parts as (string | Node)[];
    const char = text[at];
    if (char === '"') {
      const end = closing(text, at);
      top.push({ out: leaf(text.slice(at, end)) });
      nodes++;
      at = end;
    } else if (char === '{' || char === '[') {
      const node: Node = { out: '', parts: [char] };
      top.push(node);
      stack.push(node);
      nodes++;
      at++;
    } else if (char === '}' || char === ']') {
      top.push(char);
      stack.pop();
      at++;
    } else if (SPACE.has(char)) {
      let end = at;
      while (SPACE.has(text[end])) end++;
      top.push(text.slice(at, end));
      at = end;
    } else if (PUNCTUATION.has(char)) {
      top.push(char);
      at++;
    } else {
      let end = at;
      while (end < text.length && !PUNCTUATION.has(text[end])) end++;
      top.push({ out: text.slice(at, end) });
      nodes++;
      at = end;
    }
  }
  return root;
}

function render(node: Node): string {
  if (!node.parts) return node.out;
  let out = '';
  for (const part of node.parts) out += typeof part === 'string' ? part : render(part);
  return out;
}

function tally(into: Map<string, Hit>, hits: Hit[]): void {
  for (const hit of hits) {
    const key = `${hit.name}\u0000${hit.form}`;
    const known = into.get(key);
    if (known) known.count += hit.count;
    else into.set(key, { ...hit });
  }
}

function scrubJson(scrubber: Scrubber, text: string): { text: string; hits: Hit[] } | null {
  try {
    JSON.parse(text);
  } catch {
    return null;
  }
  const hits = new Map<string, Hit>();
  let budget = 4 * text.length + SLACK;
  const scan = (input: string) => {
    budget -= input.length;
    if (budget < 0) over();
    return scrubber.text(input);
  };
  const scrub = (input: string) => {
    const out = scan(input);
    tally(hits, out.hits);
    return out;
  };
  const leaf = (token: string) => {
    const out = scrub(JSON.parse(token) as string);
    return out.hits.length ? JSON.stringify(out.text) : token;
  };
  const holds = (node: Node) => scan(render(node)).hits.length > 0;
  const fix = (node: Node): boolean => {
    if (!holds(node)) return false;
    for (const part of node.parts ?? []) if (typeof part !== 'string') fix(part);
    if (node.parts && !holds(node)) return true;
    node.out = JSON.stringify(scrub(render(node)).text);
    node.parts = undefined;
    return true;
  };
  try {
    const root = tree(text, leaf);
    const out = fix(root) ? scrub(render(root)).text : render(root);
    return { text: out, hits: [...hits.values()] };
  } catch (error) {
    if (error instanceof RangeError) return null;
    throw error;
  }
}

function decoded(body: Uint8Array): string | null {
  try {
    return decoder.decode(body);
  } catch {
    return null;
  }
}

export function scrubText(scrubber: Scrubber, text: string): { text: string; hits: Hit[] } {
  return scrubJson(scrubber, text) ?? scrubber.text(text);
}

export function scrubBytes(
  scrubber: Scrubber,
  bytes: Uint8Array
): { bytes: Uint8Array; hits: Hit[] } {
  const text = decoded(bytes);
  const json = text === null ? null : scrubJson(scrubber, text);
  return json ? { bytes: encoder.encode(json.text), hits: json.hits } : scrubber.bytes(bytes);
}
