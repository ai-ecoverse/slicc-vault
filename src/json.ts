import type { Hit, Scrubber } from '@ai-ecoverse/slicc-scrub';

interface Tree {
  text: string;
  start: number[];
  end: number[];
  parent: number[];
}

interface Part {
  start: number;
  end: number;
  text: string;
}

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const SPACE = new Set([' ', '\t', '\n', '\r']);
const PUNCTUATION = new Set([...'{}[]:,"', ...SPACE]);
const NODES = 200_000;
const SLACK = 1024 * 1024;
const WINDOW = 32;

function closing(text: string, from: number): number {
  let at = from + 1;
  while (text[at] !== '"') at += text[at] === '\\' ? 2 : 1;
  return at + 1;
}

function over(): never {
  throw new RangeError('the JSON body is too large to scrub by its strings');
}

function tree(text: string, leaf: (token: string) => string): Tree {
  const pieces: string[] = [];
  const start = [0];
  const end = [0];
  const parent = [-1];
  const open = [0];
  let length = 0;
  let at = 0;
  const node = () => {
    if (start.length > NODES) over();
    start.push(length);
    end.push(length);
    parent.push(open[open.length - 1]);
    return start.length - 1;
  };
  const add = (id: number, piece: string) => {
    pieces.push(piece);
    length += piece.length;
    end[id] = length;
  };
  while (at < text.length) {
    const char = text[at];
    let stop = at + 1;
    if (char === '"') {
      stop = closing(text, at);
      add(node(), leaf(text.slice(at, stop)));
    } else if (char === '{' || char === '[') {
      const id = node();
      open.push(id);
      add(id, char);
    } else if (char === '}' || char === ']') {
      add(open.pop() as number, char);
    } else if (SPACE.has(char)) {
      while (SPACE.has(text[stop])) stop++;
      add(0, text.slice(at, stop));
    } else if (PUNCTUATION.has(char)) {
      add(0, char);
    } else {
      while (stop < text.length && !PUNCTUATION.has(text[stop])) stop++;
      add(node(), text.slice(at, stop));
    }
    at = stop;
  }
  end[0] = length;
  return { text: pieces.join(''), start, end, parent };
}

function tally(into: Map<string, Hit>, hits: Hit[]): void {
  for (const hit of hits) {
    const key = `${hit.name}\u0000${hit.form}`;
    const known = into.get(key);
    if (known) known.count += hit.count;
    else into.set(key, { ...hit });
  }
}

function compose(text: string, from: number, to: number, parts: Part[]): string {
  let out = '';
  let at = from;
  for (const part of parts) {
    out += text.slice(at, part.start) + part.text;
    at = part.end;
  }
  return out + text.slice(at, to);
}

function scrubJson(scrubber: Scrubber, text: string): { text: string; hits: Hit[] } | null {
  try {
    JSON.parse(text);
  } catch {
    return null;
  }
  const hits = new Map<string, Hit>();
  let budget = 4 * text.length + SLACK;
  const spend = (cost: number) => {
    budget -= cost;
    if (budget < 0) over();
  };
  const scan = (input: string) => {
    spend(input.length);
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
  try {
    const { text: body, start, end, parent } = tree(text, leaf);
    const holds = (from: number, to: number) => scan(body.slice(from, to)).hits.length > 0;
    const first = scan(body);
    if (!first.hits.length) return { text: body, hits: [...hits.values()] };
    const parts: Part[] = [];
    let at = 0;
    let rest = first.text;
    let derived = false;
    const differ = () => {
      let i = 0;
      while (at + i < body.length && body[at + i] === rest[i]) i++;
      spend(i);
      return at + i === body.length && i === rest.length ? -1 : at + i;
    };
    const locate = (point: number): [number, number] | null => {
      let from = at;
      let to = body.length;
      for (let width = WINDOW; ; width *= 2) {
        from = Math.max(at, point - width);
        to = Math.min(body.length, point + width);
        if (holds(from, to)) break;
        if (from === at && to === body.length) return null;
      }
      let low = from;
      let high = to - 1;
      while (low < high) {
        const mid = (low + high + 1) >> 1;
        if (holds(mid, to)) low = mid;
        else high = mid - 1;
      }
      from = low;
      high = to;
      low = from + 1;
      while (low < high) {
        const mid = (low + high) >> 1;
        if (holds(from, mid)) high = mid;
        else low = mid + 1;
      }
      return [from, high];
    };
    const smallest = (from: number, to: number) => {
      let low = 0;
      let high = start.length - 1;
      while (low < high) {
        const mid = (low + high + 1) >> 1;
        if (start[mid] <= from) low = mid;
        else high = mid - 1;
      }
      while (start[low] > from || end[low] < to) {
        spend(1);
        low = parent[low];
      }
      return low;
    };
    for (;;) {
      const point = differ();
      if (point < 0) break;
      const span = locate(point);
      if (!span) {
        if (!derived) break;
        rest = scan(body.slice(at)).text;
        derived = false;
        continue;
      }
      const id = smallest(span[0], span[1]);
      const from = start[id];
      const to = end[id];
      let inner = parts.length;
      while (inner && parts[inner - 1].start >= from) inner--;
      const out = scrub(compose(body, from, to, parts.splice(inner))).text;
      parts.push({ start: from, end: to, text: JSON.stringify(out) });
      derived = from >= at && from <= point && rest.startsWith(out, from - at);
      rest = derived ? rest.slice(from - at + out.length) : scan(body.slice(to)).text;
      at = to;
    }
    return { text: scrub(compose(body, 0, body.length, parts)).text, hits: [...hits.values()] };
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
