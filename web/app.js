// Crypto utilities (mod 26)
const MOD = 26;
const VALID_A = [1,3,5,7,9,11,15,17,19,21,23,25];

const mod = (a, m) => ((a % m) + m) % m;
const modAdd = (a, b, m) => mod(mod(a, m) + mod(b, m), m);
const modSub = (a, b, m) => mod(mod(a, m) - mod(b, m), m);
const modMul = (a, b, m) => mod(mod(a, m) * mod(b, m), m);
const egcd = (a, b) => {
  if (b === 0) return [Math.abs(a), a > 0 ? 1 : -1, 0];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - Math.floor(a / b) * y1];
};
const modInv = (a, m) => {
  const [g, x] = egcd(mod(a, m), m);
  if (g !== 1) throw new Error(`a=${a} no tiene inverso módulo ${m}`);
  return mod(x, m);
};

const charToNum = (c) => c.toUpperCase().charCodeAt(0) - 65;
const numToChar = (n, isUpper=true) => {
  const ch = String.fromCharCode(mod(n, 26) + 65);
  return isUpper ? ch : ch.toLowerCase();
};

function caesarEncrypt(text, k) {
  k = mod(k, MOD);
  let out = '';
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      const p = charToNum(ch);
      const c = modAdd(p, k, MOD);
      out += numToChar(c, ch === ch.toUpperCase());
    } else {
      out += ch;
    }
  }
  return out;
}

function caesarDecrypt(text, k) {
  k = mod(k, MOD);
  let out = '';
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      const c = charToNum(ch);
      const p = modSub(c, k, MOD);
      out += numToChar(p, ch === ch.toUpperCase());
    } else {
      out += ch;
    }
  }
  return out;
}

function affineEncrypt(text, a, b) {
  a = mod(a, MOD);
  b = mod(b, MOD);
  if (!VALID_A.includes(a)) throw new Error("La clave 'a' debe ser coprima con 26");
  let out = '';
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      const x = charToNum(ch);
      const c = modAdd(modMul(a, x, MOD), b, MOD);
      out += numToChar(c, ch === ch.toUpperCase());
    } else {
      out += ch;
    }
  }
  return out;
}

function affineDecrypt(text, a, b) {
  a = mod(a, MOD);
  b = mod(b, MOD);
  if (!VALID_A.includes(a)) throw new Error("La clave 'a' debe ser coprima con 26");
  const aInv = modInv(a, MOD);
  let out = '';
  for (const ch of text) {
    if (/[a-zA-Z]/.test(ch)) {
      const y = charToNum(ch);
      const p = modMul(aInv, modSub(y, b, MOD), MOD);
      out += numToChar(p, ch === ch.toUpperCase());
    } else {
      out += ch;
    }
  }
  return out;
}

function allCaesarShifts(text) {
  const results = [];
  for (let k=0;k<26;k++) {
    results.push({ key: k, text: caesarDecrypt(text, k) });
  }
  return results;
}

function allAffineBForA(text, a) {
  const results = [];
  for (let b=0;b<26;b++) {
    try {
      results.push({ key: `b=${b}`, text: affineDecrypt(text, a, b) });
    } catch {
      results.push({ key: `b=${b}`, text: '[error]' });
    }
  }
  return results;
}

// UI wiring
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const inputText = $('#inputText');
const outputText = $('#outputText');
const algorithm = $('#algorithm');
const caesarKeys = $('#caesarKeys');
const affineKeys = $('#affineKeys');
const kRange = $('#kRange');
const kInput = $('#kInput');
const suggestK = $('#suggestK');
const aSelect = $('#aSelect');
const bRange = $('#bRange');
const bInput = $('#bInput');
const bruteTitle = $('#bruteTitle');
const bruteList = $('#bruteList');

const encryptBtn = $('#encryptBtn');
const decryptBtn = $('#decryptBtn');
const swapBtn = $('#swapBtn');
const copyBtn = $('#copyBtn');
const saveBtn = $('#saveBtn');
const fileInput = $('#fileInput');

const darkToggle = $('#darkToggle');

const modCalcModal = $('#modCalcModal');
const aboutModal = $('#aboutModal');
const openModCalc = $('#openModCalc');
const aboutBtn = $('#aboutBtn');

// Populate a values
function initAValues() {
  aSelect.innerHTML = VALID_A.map(v => `<option value="${v}">${v}</option>`).join('');
  aSelect.value = '5';
}

function toggleAlgoUI() {
  const isCaesar = algorithm.value === 'caesar';
  caesarKeys.hidden = !isCaesar;
  affineKeys.hidden = isCaesar;
  bruteTitle.textContent = isCaesar ? 'Fuerza bruta (todas las K)' : 'Fuerza bruta Afin (variando b, a fijo)';
  updateBruteforce();
}

function syncK(val) {
  const v = ((+val)%26+26)%26;
  kRange.value = String(v);
  kInput.value = String(v);
}

function syncB(val) {
  const v = ((+val)%26+26)%26;
  bRange.value = String(v);
  bInput.value = String(v);
}

function updateBruteforce() {
  const text = inputText.value.trimEnd();
  bruteList.innerHTML = '';
  if (!text) return;
  if (algorithm.value === 'caesar') {
    const items = allCaesarShifts(text);
    for (const it of items) {
      const div = document.createElement('div');
      div.className = 'brute-item';
      div.innerHTML = `<span class="brute-key">K=${it.key}</span><span class="brute-text">${escapeHtml(it.text)}</span>`;
      div.addEventListener('click', () => {
        outputText.value = it.text;
      });
      bruteList.appendChild(div);
    }
  } else {
    const a = parseInt(aSelect.value, 10) || 1;
    const items = allAffineBForA(text, a);
    for (const it of items) {
      const div = document.createElement('div');
      div.className = 'brute-item';
      div.innerHTML = `<span class="brute-key">${it.key}</span><span class="brute-text">${escapeHtml(it.text)}</span>`;
      div.addEventListener('click', () => {
        outputText.value = it.text;
      });
      bruteList.appendChild(div);
    }
  }
}

function escapeHtml(s) {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function encrypt() {
  const text = inputText.value.trimEnd();
  if (!text) return;
  try {
    if (algorithm.value === 'caesar') {
      const k = parseInt(kInput.value, 10) || 0;
      outputText.value = caesarEncrypt(text, k);
    } else {
      const a = parseInt(aSelect.value, 10) || 1;
      const b = parseInt(bInput.value, 10) || 0;
      outputText.value = affineEncrypt(text, a, b);
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

function decrypt() {
  const text = inputText.value.trimEnd();
  if (!text) return;
  try {
    if (algorithm.value === 'caesar') {
      const k = parseInt(kInput.value, 10) || 0;
      outputText.value = caesarDecrypt(text, k);
    } else {
      const a = parseInt(aSelect.value, 10) || 1;
      const b = parseInt(bInput.value, 10) || 0;
      outputText.value = affineDecrypt(text, a, b);
    }
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

function swapIO() {
  const i = inputText.value;
  const o = outputText.value;
  inputText.value = o;
  outputText.value = i;
  updateBruteforce();
}

function copyResult() {
  const text = outputText.value;
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    toast('Resultado copiado');
  });
}

function saveResult() {
  const text = outputText.value;
  if (!text) return;
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'resultado.txt';
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function openFile(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    inputText.value = reader.result;
    updateBruteforce();
  };
  reader.readAsText(file, 'utf-8');
}

function suggestKey() {
  const text = inputText.value;
  const letters = [...text].filter(ch => /[a-zA-Z]/.test(ch)).map(ch => ch.toUpperCase());
  if (letters.length === 0) { toast('No hay letras para analizar'); return; }
  const counts = new Map();
  for (const ch of letters) counts.set(ch, (counts.get(ch)||0) + 1);
  const most = [...counts.entries()].sort((a,b)=>b[1]-a[1])[0][0];
  const idx = most.charCodeAt(0) - 65;
  const candidates = ['E','A','O'];
  const suggestions = candidates.map(p => ({ plain: p, k: mod(idx - (p.charCodeAt(0)-65), 26) }));
  const best = suggestions[0];
  syncK(best.k);
  toast(`Más frecuente: ${most}. Si es '${best.plain}', K ≈ ${best.k}`);
}

// Dark mode
function initTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.dataset.theme = saved;
  darkToggle.textContent = saved === 'dark' ? '🌙' : '☀️';
}
function toggleTheme() {
  const current = document.documentElement.dataset.theme || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('theme', next);
  darkToggle.textContent = next === 'dark' ? '🌙' : '☀️';
}

// Simple toast
let toastTimer;
function toast(msg) {
  let el = document.getElementById('toast');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast';
    el.style.position = 'fixed';
    el.style.bottom = '20px';
    el.style.left = '50%';
    el.style.transform = 'translateX(-50%)';
    el.style.padding = '10px 14px';
    el.style.background = 'rgba(0,0,0,0.6)';
    el.style.color = 'white';
    el.style.borderRadius = '10px';
    el.style.zIndex = '2000';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.opacity = '1';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{ el.style.opacity = '0'; }, 1600);
}

// Modals
function openModal(el) { el.hidden = false; }
function closeModal(el) { el.hidden = true; }

function setupModals() {
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.closest('.modal')));
  });
  document.querySelectorAll('.modal-backdrop').forEach(b => {
    b.addEventListener('click', () => closeModal(b.closest('.modal')));
  });
  openModCalc.addEventListener('click', (e)=>{ e.preventDefault(); openModal(modCalcModal); });
  aboutBtn.addEventListener('click', (e)=>{ e.preventDefault(); openModal(aboutModal); });
}

function computeModCalc() {
  const m = parseInt($('#mInput').value, 10);
  const op = $('#opSelect').value;
  const a = parseInt($('#maInput').value, 10);
  const b = parseInt($('#mbInput').value, 10);
  try {
    if (!(m > 0)) throw new Error('m debe ser positivo');
    let res;
    if (op === 'a + b (mod m)') res = modAdd(a, b, m);
    else if (op === 'a - b (mod m)') res = modSub(a, b, m);
    else if (op === 'a * b (mod m)') res = modMul(a, b, m);
    else if (op === 'a^b (mod m)') res = BigInt(a) ** BigInt(b) % BigInt(m);
    else res = modInv(a, m);
    $('#calcResult').textContent = `= ${res.toString()}`;
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// Events
function setupEvents() {
  algorithm.addEventListener('change', toggleAlgoUI);

  kRange.addEventListener('input', e => syncK(e.target.value));
  kInput.addEventListener('input', e => syncK(e.target.value));
  bRange.addEventListener('input', e => syncB(e.target.value));
  bInput.addEventListener('input', e => syncB(e.target.value));
  aSelect.addEventListener('change', updateBruteforce);

  inputText.addEventListener('input', updateBruteforce);

  encryptBtn.addEventListener('click', encrypt);
  decryptBtn.addEventListener('click', decrypt);
  swapBtn.addEventListener('click', swapIO);
  copyBtn.addEventListener('click', copyResult);
  saveBtn.addEventListener('click', saveResult);
  fileInput.addEventListener('change', openFile);

  suggestK.addEventListener('click', suggestKey);

  darkToggle.addEventListener('click', toggleTheme);

  $('#calcBtn').addEventListener('click', computeModCalc);
}

function init() {
  initTheme();
  initAValues();
  setupEvents();
  setupModals();
  toggleAlgoUI();
  updateBruteforce();
}

document.addEventListener('DOMContentLoaded', init);
