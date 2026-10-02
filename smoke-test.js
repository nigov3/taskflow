// Дымовой тест: рендерим App в jsdom с мок-супейбасом и проверяем экраны доступа.
const fs = require('fs');
const { JSDOM } = require('jsdom');
const babel = require('@babel/standalone');
const React = require('react');
const ReactDOM = require('react-dom/client');

const html = fs.readFileSync('index.html', 'utf8');
const src = html.match(/<script type="text\/babel">([\s\S]*?)<\/script>/)[1];

const dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>', { url: 'http://localhost/', pretendToBeVisual: true });
global.window = dom.window; global.document = dom.window.document; global.navigator = dom.window.navigator;
global.localStorage = dom.window.localStorage; global.crypto = dom.window.crypto || require('crypto').webcrypto;
dom.window.crypto = dom.window.crypto || global.crypto;
Object.defineProperty(dom.window, 'isSecureContext', { value: true });
global.TextEncoder = TextEncoder;

// --- Мок Supabase ---
let currentProfile = { id: 'u2', name: 'Коллега', email: 'k@x.com', role: 'pending' };
const listeners = [];
const table = (rows) => {
  const q = {
    then: (res) => Promise.resolve(res({ data: rows, error: null })),
    eq: () => q,
    maybeSingle: () => Promise.resolve({ data: Array.isArray(rows) ? (rows[0] || null) : rows, error: null }),
    select: () => q, update: () => q, insert: () => q, delete: () => q, upsert: () => q,
  };
  return q;
};
const mockSb = {
  auth: {
    getSession: async () => ({ data: { session: { user: { id: 'u2', email: 'k@x.com' } } } }),
    onAuthStateChange: (cb) => { listeners.push(cb); return { data: { subscription: { unsubscribe(){} } } }; },
    signOut: async () => {},
    signInWithPassword: async () => ({ error: null }),
    signUp: async () => ({ data: { session: {} }, error: null }),
  },
  from: (name) => {
    if (name === 'profiles') return table(currentProfile.role === '__none__' ? null : [currentProfile]);
    if (name === 'app_state') return table(null); // доступ закрыт — сервер вернёт null
    return table([]);
  },
  channel: () => ({ on: () => ({ subscribe: () => {}, }), }),
  removeChannel: () => {},
};
dom.window.supabase = { createClient: () => mockSb };

// Подменяем URL/KEY через замену строк в исходнике
const patched = src.replace("const SUPABASE_URL = 'XXX';", "const SUPABASE_URL = 'https://test.supabase.co';")
                   .replace("const SUPABASE_KEY = 'XXX';", "const SUPABASE_KEY = 'testkey';");

const out = babel.transform(patched, { presets: ['react'] }).code;
const run = new Function('React', 'ReactDOM', 'window', 'document', 'localStorage', 'crypto', 'navigator', 'TextEncoder', 'alert', 'confirm', 'fetch', out + '\nreturn App;');
const alertCalls = [];
const App = run(React, ReactDOM, dom.window, dom.window.document, dom.window.localStorage, global.crypto, dom.window.navigator, TextEncoder,
  (m)=>alertCalls.push(m), ()=>true, async ()=>({ ok:true }));

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));

setTimeout(() => {
  const text = document.body.textContent || '';
  console.log('--- pending screen shown:', text.includes('Доступ ещё не выдан'));
  console.log('--- tasks hidden (no kanban columns):', !text.includes('К выполнению'));
  console.log('--- login button absent for signed-in pending:', !text.includes('Войти / зарегистрироваться'));
  process.exit(text.includes('Доступ ещё не выдан') ? 0 : 1);
}, 800);
