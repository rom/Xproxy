// A DOM small enough to render the admin page, and no smaller.
//
// The point is not to be a browser: it is to run every view's render()
// against a fixture and fail if one throws. A view that reads a field the
// management API does not have, or calls a helper with the wrong shape,
// fails here rather than in front of an operator with an empty card.
'use strict';

class Node {
  constructor() { this.childNodes = []; }
  get firstChild() { return this.childNodes[0] || null; }
  removeChild(c) { this.childNodes = this.childNodes.filter(x => x !== c); return c; }
  append(...cs) {
    for (const c of cs) this.childNodes.push(c instanceof Node ? c : new Text(String(c)));
  }
  get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.childNodes = [new Text(String(v))]; }
}
class Text extends Node {
  constructor(v) { super(); this.value = String(v); }
  get textContent() { return this.value; }
}
class ClassList {
  constructor(el) { this.el = el; }
  add(...cs) { this.el._classes = new Set([...this.el._classes, ...cs]); }
  remove(...cs) { for (const c of cs) this.el._classes.delete(c); }
  toggle(c, on) { if (on) this.add(c); else this.el._classes.delete(c); }
  contains(c) { return this.el._classes.has(c); }
}
class Element extends Node {
  constructor(tag) {
    super();
    this.tagName = String(tag).toUpperCase();
    this.attrs = {};
    this._classes = new Set();
    this.classList = new ClassList(this);
    this.style = {};
    this.clientWidth = 400; this.clientHeight = 160;
    this.scrollTop = 0; this.scrollHeight = 0;
    this.value = '';
    this.selectionStart = 0; this.selectionEnd = 0;
  }
  get childElementCount() { return this.childNodes.filter(c => c instanceof Element).length; }
  setRangeText() {}
  get className() { return [...this._classes].join(' '); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k === 'class' ? this.className : (this.attrs[k] ?? null); }
  addEventListener() {}
  // A canvas is drawn to and never read back, so every 2d call is a no-op.
  getContext() {
    const noop = () => {};
    return new Proxy({}, { get: (_, k) => (k === 'canvas' ? this : noop), set: () => true });
  }
  descendants() {
    const out = [];
    const walk = n => { for (const c of n.childNodes) { if (c instanceof Element) { out.push(c); walk(c); } } };
    walk(this);
    return out;
  }
  matches(sel) {
    if (sel.startsWith('#')) return this.attrs.id === sel.slice(1);
    const [tag, ...cls] = sel.split('.');
    if (tag && this.tagName !== tag.toUpperCase()) return false;
    return cls.every(c => this._classes.has(c));
  }
  querySelector(sel) { return this.descendants().find(e => e.matches(sel)) || null; }
  querySelectorAll(sel) { return this.descendants().filter(e => e.matches(sel)); }
}

const root = new Element('body');
const byID = {};
function el(tag, id) {
  const e = new Element(tag);
  if (id) { e.setAttribute('id', id); byID[id] = e; root.append(e); }
  return e;
}

// The identifiers app.js looks up at load time and on every render.
for (const id of ['view', 'nav', 'flash', 'app', 'login', 'login-form', 'login-error',
  'sso', 'sso-link', 'who', 'footer-version', 'refresh-state', 'logout']) el('div', id);

const document = {
  createElement: t => new Element(t),
  createTextNode: v => new Text(v),
  documentElement: new Element('html'),
  // byID for the fixed identifiers, then the tree, because a view creates
  // elements with identifiers of its own and then looks them up.
  querySelector: sel => (sel.startsWith('#') && byID[sel.slice(1)]) || root.querySelector(sel),
  addEventListener() {},
};
globalThis.Node = Node;
globalThis.document = document;
globalThis.window = { addEventListener() {}, devicePixelRatio: 1 };
globalThis.location = { hash: '', search: '', pathname: '/' };
globalThis.history = { replaceState() {} };
// navigator is a getter on globalThis in Node, so it is defined rather
// than assigned.
Object.defineProperty(globalThis, 'navigator', {
  value: { clipboard: { writeText: async () => {} } }, configurable: true,
});
globalThis.getComputedStyle = () => ({ getPropertyValue: () => '#000' });
globalThis.EventSource = class { constructor() {} close() {} };
globalThis.URLSearchParams = URLSearchParams;
globalThis.confirm = () => true;
globalThis.setInterval = () => 0;
globalThis.clearInterval = () => {};
globalThis.setTimeout = () => 0;
globalThis.clearTimeout = () => {};
globalThis.alert = () => {};

// The fixtures, and the fetch that answers from them. A path with no
// fixture answers 404, which is how a view learns a subsystem is not
// configured -- so every view is rendered twice in effect: once with data
// and, for the endpoints the fixture leaves out, once without.
const fixtures = JSON.parse(require('fs').readFileSync(process.argv[3], 'utf8'));
globalThis.fetch = async (path, opts) => {
  const key = path.replace(/\?.*$/, '');
  const has = Object.prototype.hasOwnProperty.call(fixtures, key);
  const body = has ? fixtures[key] : { error: 'not configured' };
  return {
    ok: has, status: has ? 200 : 404,
    headers: { get: () => 'application/json' },
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
};

const src = require('fs').readFileSync(process.argv[2], 'utf8');
// app.js is a script, not a module: evaluate it and take the views out of
// its scope by returning them.
// me is app.js's own variable, assigned here from inside its scope: the
// views ask it for the role, which decides whether the operator controls
// are drawn. Operator draws the most, so that is what is rendered.
const epilogue = `
  me = {user: 'op', role: 'operator', via: 'password', version: 'test',
        can_restart: true, can_edit_file: true};
  return views;`;
const views = new Function(src + epilogue)();

(async () => {
  const names = Object.keys(views).sort();
  const failed = [];
  for (const name of names) {
    byID.view.childNodes = [];
    try {
      await views[name].render();
      if (!byID.view.childNodes.length) failed.push(name + ': rendered nothing');
    } catch (e) {
      failed.push(name + ': ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e));
    }
  }
  if (failed.length) {
    console.log('FAIL\n' + failed.join('\n'));
    process.exit(1);
  }
  console.log('OK ' + names.length + ' views: ' + names.join(' '));
})();
