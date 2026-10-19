// Exercise the actual TSX with a minimal Decky/React host. No Steam session,
// network engine, test framework or extra dependencies are required.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../decky/package.json', import.meta.url));
const ts = require('typescript');
const catalogue = JSON.parse(fs.readFileSync(new URL('../helmsman/locales/en.json', import.meta.url)));
function compile(path, dependencies, globals = {}) {
  const source = fs.readFileSync(new URL(path, import.meta.url), 'utf8');
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  const exports = {};
  vm.runInNewContext(code, { exports, require: name => {
    assert.ok(name in dependencies, name); return dependencies[name];
  }, ...globals });
  return exports;
}
const { translator } = compile('../decky/src/i18n.ts', { '../../helmsman/locales/en.json': catalogue });
assert.equal(translator('en')('Ошибка системного компонента: sing-box (код 1).'), 'System component error: sing-box (code 1).');
let service = { state: 'disconnected', message: '', desired: false, guard: false, auto_connect: false,
  selected: 'p', preset: 'ru-selective', country: 'ru', language: 'ru',
  profiles: [{ id: 'p', name: 'Ошибка', protocol: 'vless' }] };
const calls = [], frames = new Map(), effects = [], memory = new Map();
let frame, changed = false;
const react = {
  useState(initial) {
    const target = frame, index = target.index++;
    if (!(index in target.state)) target.state[index] = typeof initial === 'function' ? initial() : initial;
    return [target.state[index], value => { target.state[index] = value; changed = true; }];
  },
  useEffect(callback, deps) {
    const index = frame.index++;
    if (!frame.deps[index] || deps.some((value, i) => value !== frame.deps[index][i])) {
      frame.deps[index] = deps; effects.push(callback);
    }
  }
};
const jsx = (type, props) => ({ type, props });
function status() {
  const t = translator(service.language);
  const names = service.country === 'ru' ? { full: 'Весь интернет через VPN', 'ru-selective': 'Россия: выборочно', manual: 'Мои правила' }
    : { full: 'Весь интернет через VPN', 'cn-except': 'Китай: домены и IP напрямую', manual: 'Мои правила' };
  return { ...service, countries: { ru: t('Россия'), cn: t('Китай') },
    presets: Object.fromEntries(Object.entries(names).map(([key, value]) => [key, t(value)])),
    preset_descriptions: Object.fromEntries(Object.keys(names).map(key => [key, t('Ваше соединение')])),
    active_preset_name: t('Россия: выборочно'), active_preset_description: t('Ваше соединение') };
}
const api = { definePlugin: callback => callback(), callable: () => async (method, params) => {
  calls.push([method, params]);
  if (method === 'preferences') service = { ...service, ...params };
  if (method === 'preset') service.preset = params.preset;
  return status();
} };
const plugin = compile('../decky/src/index.tsx', {
  '@decky/api': api, '@decky/ui': Object.fromEntries(['ButtonItem', 'DropdownItem', 'PanelSection', 'PanelSectionRow', 'TextField', 'ToggleField'].map(name => [name, name]).concat([['staticClasses', { Title: 'title' }]])),
  react, 'react/jsx-runtime': { jsx, jsxs: jsx, Fragment: 'fragment' }, './i18n': { translator }
}, { localStorage: { getItem: key => memory.get(key), setItem: (key, value) => memory.set(key, value) }, setInterval: () => 1, clearInterval: () => {} }).default;
let nodes = [];
function walk(node) {
  if (node == null || typeof node === 'boolean') return;
  if (Array.isArray(node)) { node.forEach(walk); return; }
  if (typeof node !== 'object') { nodes.push({ text: String(node) }); return; }
  if (typeof node.type === 'function') {
    if (!frames.has(node.type)) frames.set(node.type, { state: [], deps: [], index: 0 });
    frame = frames.get(node.type); frame.index = 0; walk(node.type(node.props)); return;
  }
  nodes.push(node); walk(node.props?.children);
}
async function render() {
  for (let i = 0; i < 10; i++) {
    changed = false; nodes = []; walk(plugin.content);
    while (effects.length) effects.shift()();
    await new Promise(resolve => setImmediate(resolve));
    if (!changed) return;
  }
  throw Error('Render did not settle');
}
const find = (type, label) => nodes.find(node => node.type === type && (node.props.label === label || node.props.children === label));
await render();
find('ButtonItem', '▸ Дополнительно').props.onClick(); await render();
find('DropdownItem', 'Язык интерфейса').props.onChange({ data: 'en' }); await render();
assert.equal(service.country, 'ru');
assert.equal(memory.get('helmsman.language'), 'en');
assert.equal(find('DropdownItem', 'Route').props.selectedOption, 'ru-selective');
find('DropdownItem', 'Routing country').props.onChange({ data: 'cn' }); await render();
assert.equal(service.preset, 'ru-selective');
assert.equal(service.language, 'en');
assert.equal(find('DropdownItem', 'Route').props.selectedOption, '');
const before = calls.filter(([method]) => method === 'preset').length;
find('DropdownItem', 'Route').props.onChange({ data: 'cn-except' }); await render();
assert.equal(calls.filter(([method]) => method === 'preset').length, before);
find('ButtonItem', 'Apply route').props.onClick(); await render();
assert.equal(service.preset, 'cn-except');
assert.ok(find('DropdownItem', 'Route').props.rgOptions.some(option => option.label === 'China: domains + IPs direct'));
assert.equal(find('DropdownItem', 'Profile').props.rgOptions[0].label, 'Ошибка');
find('ButtonItem', '▸ Create Cloudflare WARP').props.onClick(); await render();
assert.ok(find('ToggleField', 'I accept the Cloudflare terms'));
for (const node of nodes) {
  if (node.text) assert.ok(!/[А-Яа-яЁё]/.test(node.text), node.text);
  if (node.type === 'div' && node.props.style?.fontSize === 12) assert.equal(node.props.style.overflowWrap, 'anywhere');
}
find('DropdownItem', 'Interface language').props.onChange({ data: 'ru' }); await render();
assert.equal(service.country, 'cn');
assert.ok(find('DropdownItem', 'Страна маршрутизации'));
console.log('PASS Decky RU/EN, shared preference RPCs, country filtering, explicit apply, user names and wrapping props (mock host)');
