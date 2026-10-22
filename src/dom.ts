type Prop = string | boolean | number | undefined | ((event: Event) => void);

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, Prop> = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (typeof value === 'function') element.addEventListener(key.slice(2), value);
    else if (value === true) element.setAttribute(key, '');
    else if (value !== false && value !== undefined) element.setAttribute(key, String(value));
  }
  for (const child of children) if (child) element.append(child);
  return element;
}

export interface Look {
  theme?: 'light' | 'dark';
  scale?: 'medium' | 'large';
  dir?: 'ltr' | 'rtl';
  lang?: string;
}

export function themed(root: HTMLElement, look: Look, dark: boolean): void {
  const theme = look.theme ?? (dark ? 'dark' : 'light');
  root.classList.add('spectrum');
  root.classList.toggle('spectrum--light', theme === 'light');
  root.classList.toggle('spectrum--dark', theme === 'dark');
  root.classList.toggle('spectrum--medium', look.scale !== 'large');
  root.classList.toggle('spectrum--large', look.scale === 'large');
  document.documentElement.classList.toggle('scheme-light', look.theme === 'light');
  document.documentElement.classList.toggle('scheme-dark', look.theme === 'dark');
  document.documentElement.dir = look.dir ?? 'ltr';
  document.documentElement.lang = look.lang ?? 'en';
}

export function prefersDark(win: Window = window): MediaQueryList {
  return win.matchMedia('(prefers-color-scheme: dark)');
}

export function button(
  label: string,
  onclick: () => void,
  variant: 'accent' | 'primary' | 'secondary' | 'negative' = 'secondary',
  treatment: 'fill' | 'outline' = 'fill'
): HTMLButtonElement {
  return h(
    'button',
    {
      type: 'button',
      class: `spectrum-Button spectrum-Button--${variant} spectrum-Button--${treatment} spectrum-Button--sizeM`,
      onclick,
    },
    h('span', { class: 'spectrum-Button-label' }, label)
  );
}

export function field(
  id: string,
  label: string,
  input: Record<string, Prop>
): { field: HTMLDivElement; input: HTMLInputElement } {
  const control = h('input', { id, class: 'spectrum-Textfield-input', ...input });
  const wrap = h(
    'div',
    { class: 'field' },
    h('label', { for: id }, label),
    h('div', { class: 'spectrum-Textfield spectrum-Textfield--sizeM' }, control)
  );
  return { field: wrap, input: control };
}

export function reloadOnRestore(win: Window = window): void {
  win.addEventListener('pageshow', (event) => {
    if ((event as PageTransitionEvent).persisted) win.location.reload();
  });
}

export function holdOutOfCache(win: Window = window): void {
  win.addEventListener('unload', () => undefined);
  reloadOnRestore(win);
}
