export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

export class TomlError extends Error {
  readonly line: number;

  constructor(message: string, line: number) {
    super(`line ${line}: ${message}`);
    this.line = line;
  }
}

const BARE = /[A-Za-z0-9_-]/;
const DATE = /^\d{4}-\d{2}-\d{2}([Tt]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:\d{2})?)?$/;
const TIME = /^\d{2}:\d{2}:\d{2}(\.\d+)?$/;
const SPECIAL = /^[+-]?(inf|nan)$/;
const RADIX = /^0([xob])([0-9A-Fa-f](_?[0-9A-Fa-f])*)$/;
const DECIMAL = /^[+-]?(0|[1-9](_?[0-9])*)(\.[0-9](_?[0-9])*)?([eE][+-]?[0-9](_?[0-9])*)?$/;
const ESCAPES: Record<string, string> = {
  b: '\b',
  t: '\t',
  n: '\n',
  f: '\f',
  r: '\r',
  '"': '"',
  '\\': '\\',
};

function table(): TomlTable {
  return Object.create(null) as TomlTable;
}

function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

class Parser {
  readonly text: string;
  pos = 0;
  readonly root = table();
  readonly fixed = new Set<TomlTable>();
  readonly declared = new Set<TomlTable>();

  constructor(text: string) {
    this.text = text;
  }

  get line(): number {
    return this.text.slice(0, this.pos).split('\n').length;
  }

  fail(message: string): never {
    throw new TomlError(message, this.line);
  }

  peek(offset = 0): string {
    return this.text[this.pos + offset] ?? '';
  }

  skipSpace(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.pos++;
  }

  skipComment(): void {
    if (this.peek() !== '#') return;
    while (this.pos < this.text.length && this.peek() !== '\n') this.pos++;
  }

  endOfLine(): void {
    this.skipSpace();
    this.skipComment();
    if (this.peek() === '\r') this.pos++;
    if (this.pos < this.text.length && this.peek() !== '\n')
      this.fail('expected the end of the line');
    this.pos++;
  }

  skipBlank(): void {
    for (;;) {
      this.skipSpace();
      this.skipComment();
      if (this.peek() === '\r' || this.peek() === '\n') this.pos++;
      else return;
    }
  }

  parse(): TomlTable {
    let current = this.root;
    for (;;) {
      this.skipBlank();
      if (this.pos >= this.text.length) return this.root;
      if (this.peek() === '[') current = this.header();
      else {
        this.pair(current);
        this.endOfLine();
      }
    }
  }

  header(): TomlTable {
    const array = this.peek(1) === '[';
    this.pos += array ? 2 : 1;
    this.skipSpace();
    const keys = this.key();
    this.skipSpace();
    if (this.text.slice(this.pos, this.pos + (array ? 2 : 1)) !== (array ? ']]' : ']')) {
      this.fail('expected the end of the table header');
    }
    this.pos += array ? 2 : 1;
    this.endOfLine();
    const parent = this.descend(this.root, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    if (array) return this.appendTable(parent, last);
    const existing = parent[last];
    const taken = isTable(existing) && (this.declared.has(existing) || this.fixed.has(existing));
    if (existing !== undefined && (!isTable(existing) || taken)) {
      this.fail(`table ${keys.join('.')} is defined twice`);
    }
    const created = isTable(existing) ? existing : table();
    parent[last] = created;
    this.declared.add(created);
    return created;
  }

  appendTable(parent: TomlTable, key: string): TomlTable {
    const existing = parent[key];
    if (existing !== undefined && !Array.isArray(existing))
      this.fail(`${key} is not an array of tables`);
    const list = (existing ?? []) as TomlValue[];
    if (this.fixed.has(list as unknown as TomlTable)) this.fail(`${key} is a fixed array`);
    const created = table();
    list.push(created);
    parent[key] = list;
    return created;
  }

  descend(start: TomlTable, keys: string[]): TomlTable {
    let node = start;
    for (const key of keys) {
      let next = node[key];
      if (next === undefined) {
        next = table();
        node[key] = next;
      }
      if (Array.isArray(next) && !this.fixed.has(next as unknown as TomlTable)) {
        next = next[next.length - 1];
      }
      if (!isTable(next) || this.fixed.has(next)) this.fail(`${key} is not a table`);
      node = next;
    }
    return node;
  }

  pair(target: TomlTable): void {
    const keys = this.key();
    this.skipSpace();
    if (this.peek() !== '=') this.fail('expected =');
    this.pos++;
    this.skipSpace();
    const value = this.value();
    const parent = this.descend(target, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    if (last in parent) this.fail(`${keys.join('.')} is defined twice`);
    parent[last] = value;
  }

  key(): string[] {
    const keys: string[] = [];
    for (;;) {
      this.skipSpace();
      if (this.peek() === '"') keys.push(this.basic());
      else if (this.peek() === "'") keys.push(this.literal());
      else {
        const start = this.pos;
        while (BARE.test(this.peek())) this.pos++;
        if (start === this.pos) this.fail('expected a key');
        keys.push(this.text.slice(start, this.pos));
      }
      this.skipSpace();
      if (this.peek() !== '.') return keys;
      this.pos++;
    }
  }

  value(): TomlValue {
    const char = this.peek();
    if (char === '"')
      return this.text.startsWith('"""', this.pos) ? this.multiline('"') : this.basic();
    if (char === "'")
      return this.text.startsWith("'''", this.pos) ? this.multiline("'") : this.literal();
    if (char === '[') return this.array();
    if (char === '{') return this.inline();
    return this.scalar();
  }

  scalar(): TomlValue {
    const match = /^[^\s,\]}#]+/.exec(this.text.slice(this.pos));
    if (!match) this.fail('expected a value');
    const token = match[0];
    this.pos += token.length;
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (DATE.test(token)) return token + this.time();
    if (TIME.test(token)) return token;
    if (SPECIAL.test(token))
      return token.endsWith('nan') ? Number.NaN : Number(token.replace('inf', 'Infinity'));
    const radix = RADIX.exec(token);
    if (radix) return this.radix(token, radix[1], radix[2]);
    if (DECIMAL.test(token)) return Number(token.replace(/_/g, ''));
    return this.fail(`unsupported value ${token}`);
  }

  time(): string {
    const time = /^ \d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:\d{2})?/.exec(
      this.text.slice(this.pos)
    );
    if (!time) return '';
    this.pos += time[0].length;
    return time[0];
  }

  radix(token: string, kind: string, raw: string): number {
    const base = kind === 'x' ? 16 : kind === 'o' ? 8 : 2;
    const digits = raw.replace(/_/g, '');
    const valid = { 16: /^[0-9A-Fa-f]+$/, 8: /^[0-7]+$/, 2: /^[01]+$/ }[base] as RegExp;
    if (!valid.test(digits)) this.fail(`bad number ${token}`);
    return Number.parseInt(digits, base);
  }

  escape(): string {
    const char = this.peek();
    this.pos++;
    if (char in ESCAPES) return ESCAPES[char];
    const length = char === 'u' ? 4 : char === 'U' ? 8 : 0;
    const digits = this.text.slice(this.pos, this.pos + length);
    if (!length || !/^[0-9A-Fa-f]+$/.test(digits) || digits.length !== length) {
      this.fail('bad escape');
    }
    this.pos += length;
    return String.fromCodePoint(Number.parseInt(digits, 16));
  }

  basic(): string {
    this.pos++;
    let out = '';
    for (;;) {
      const char = this.peek();
      if (char === '' || char === '\n') this.fail('unterminated string');
      this.pos++;
      if (char === '"') return out;
      out += char === '\\' ? this.escape() : char;
    }
  }

  literal(): string {
    this.pos++;
    const end = this.text.indexOf("'", this.pos);
    const newline = this.text.indexOf('\n', this.pos);
    if (end < 0 || (newline >= 0 && newline < end)) this.fail('unterminated string');
    const out = this.text.slice(this.pos, end);
    this.pos = end + 1;
    return out;
  }

  multiline(quote: string): string {
    const fence = quote.repeat(3);
    this.pos += 3;
    if (this.peek() === '\r') this.pos++;
    if (this.peek() === '\n') this.pos++;
    const end = this.text.indexOf(fence, this.pos);
    if (end < 0) this.fail('unterminated string');
    if (quote === "'") {
      const raw = this.text.slice(this.pos, end);
      this.pos = end + 3;
      return raw;
    }
    let out = '';
    while (!this.text.startsWith(fence, this.pos)) {
      const char = this.peek();
      if (char === '') this.fail('unterminated string');
      this.pos++;
      if (char !== '\\') out += char;
      else if (/[\s]/.test(this.peek())) {
        while (/[\s]/.test(this.peek())) this.pos++;
      } else out += this.escape();
    }
    this.pos += 3;
    return out;
  }

  array(): TomlValue[] {
    this.pos++;
    const out: TomlValue[] = [];
    for (;;) {
      this.skipBlank();
      if (this.peek() === ']') break;
      out.push(this.value());
      this.skipBlank();
      if (this.peek() === ',') this.pos++;
      else if (this.peek() !== ']') this.fail('expected , or ]');
    }
    this.pos++;
    this.fixed.add(out as unknown as TomlTable);
    return out;
  }

  inline(): TomlTable {
    this.pos++;
    const out = table();
    this.skipSpace();
    if (this.peek() === '}') {
      this.pos++;
      this.fixed.add(out);
      return out;
    }
    for (;;) {
      this.pair(out);
      this.skipSpace();
      const char = this.peek();
      this.pos++;
      if (char === '}') break;
      if (char !== ',') this.fail('expected , or }');
    }
    this.fixed.add(out);
    return out;
  }
}

export function parseToml(text: string): TomlTable {
  return new Parser(text).parse();
}
