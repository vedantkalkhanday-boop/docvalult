/* DocVault: an offline, encrypted locker for personal documents.
 *
 * Security model
 *  - A random 256-bit AES-GCM data key (DEK) encrypts every record: document
 *    details (title, number, notes…), every file, and every thumbnail.
 *  - The DEK is only ever stored "wrapped" (encrypted) with a key derived from
 *    the master password using PBKDF2-SHA256, 600,000 iterations, random salt.
 *  - Each ciphertext is bound to its record id (AES-GCM additional data), so
 *    encrypted records cannot be swapped around on disk.
 *  - Changing the password only re-wraps the DEK; files are not re-encrypted.
 *  - The page's Content-Security-Policy forbids talking to any other host, so
 *    nothing can leave the device. Backups are the same ciphertext, packed into
 *    one file that only opens with the master password.
 */
'use strict';
(() => {

// ---------------------------------------------------------------- constants
const DB_NAME = 'docvault';
const KDF_ITER = 600000;
const MAX_DIM = 2400;              // longest side of stored photos when shrinking
const THUMB_DIM = 480;
const EXPIRY_WARN_DAYS = 60;
const BACKUP_NAG_DAYS = 30;
const DEFAULT_SETTINGS = { autolock: 5, lockOnHide: false, compress: true, lastBackup: null };

const CATEGORY_ICONS = {
  Identity: '🪪', Education: '🎓', Medical: '🏥', Financial: '💰', Bank: '🏦',
  Property: '🏠', Vehicle: '🚗', Insurance: '🛡️', Certificates: '📜',
  'Bills & Receipts': '🧾', Travel: '✈️', Work: '💼', Other: '📁',
};
const CATEGORY_ORDER = Object.keys(CATEGORY_ICONS);
const QUICK_TEMPLATES = [
  ['Aadhaar Card', 'Identity'], ['PAN Card', 'Identity'], ['Passport', 'Identity'],
  ['Voter ID', 'Identity'], ['Driving Licence', 'Identity'], ['Ration Card', 'Identity'],
  ['Birth Certificate', 'Certificates'], ['10th Marksheet', 'Education'],
  ['12th Marksheet', 'Education'], ['Degree Certificate', 'Education'],
  ['Vehicle RC', 'Vehicle'], ['Health Insurance', 'Insurance'],
  ['Bank Passbook', 'Bank'], ['Property Papers', 'Property'],
];

// ---------------------------------------------------------------- state
let db = null;
let dek = null;                    // CryptoKey, present only while unlocked
const docs = new Map();            // id -> decrypted document details
let settings = { ...DEFAULT_SETTINGS };
let filter = { cat: 'all', member: 'all', q: '' };
const thumbUrls = new Map();       // fileId -> object URL (revoked on lock)
let editing = null;                // the document being added/edited
let viewingId = null;
let imageView = null;              // { files, index, blob, url }
let backupMode = 'merge';
let lastActive = Date.now();
let pickingSince = 0;              // a file/camera picker is open: don't auto-lock under it

// ---------------------------------------------------------------- small helpers
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const te = new TextEncoder();
const td = new TextDecoder();
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const uid = () => Array.from(rand(12), b => b.toString(16).padStart(2, '0')).join('');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const catIcon = c => CATEGORY_ICONS[c] || '📁';
const isPdf = f => f.type === 'application/pdf' || /\.pdf$/i.test(f.name);
// Shown in the built-in viewer only if the browser could decode it (it then has a thumbnail).
const isViewableImage = f => /^image\//.test(f.type) && !!f.thumb;
const isTouch = () => matchMedia('(pointer: coarse)').matches;

function fmtDate(iso) {
  if (!iso) return '';
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}
const fmtDateTime = ts => ts ? new Date(ts).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '';
function fmtSize(n) {
  if (!n && n !== 0) return '?';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
function maskNumber(num) {
  const s = String(num || '').trim();
  return s.length > 4 ? '•••• ' + s.slice(-4) : s;
}
function daysLeft(iso) {
  if (!iso) return null;
  const [y, m, d] = iso.split('-').map(Number);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  return Math.round((new Date(y, m - 1, d) - today) / 864e5);
}
function expiryState(d) {
  const n = daysLeft(d.expiry);
  if (n === null) return null;
  if (n < 0) return { cls: 'expired', text: 'Expired' };
  if (n <= EXPIRY_WARN_DAYS) return { cls: '', text: n === 0 ? 'Expires today' : `Expires in ${n} day${n === 1 ? '' : 's'}` };
  return null;
}

function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
// Records hold binary in these fields; backups carry them as base64.
const BINARY_FIELDS = ['iv', 'ct', 'salt', 'wrapped'];
const pack = rec => Object.fromEntries(Object.entries(rec).map(([k, v]) => [k, BINARY_FIELDS.includes(k) ? b64(v) : v]));
const unpack = rec => Object.fromEntries(Object.entries(rec).map(([k, v]) => [k, BINARY_FIELDS.includes(k) ? unb64(v) : v]));

// ---------------------------------------------------------------- IndexedDB
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const d = req.result;
      d.createObjectStore('meta');                                         // vault key + settings
      d.createObjectStore('docs', { keyPath: 'id' });                      // {id, iv, ct}
      d.createObjectStore('files', { keyPath: 'id' }).createIndex('docId', 'docId'); // {id, docId, iv, ct}
      d.createObjectStore('thumbs', { keyPath: 'id' });                    // {id, iv, ct}
    };
    req.onsuccess = () => {
      const d = req.result;
      // Another window is erasing or upgrading the vault: step aside so it isn't blocked forever.
      d.onversionchange = () => { d.close(); location.reload(); };
      resolve(d);
    };
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('Close other Doc Vault windows and try again.'));
  });
}

// Runs fn inside one transaction; resolves with the last request's result once committed.
// fn must only queue IDB requests (no awaits), or the transaction auto-commits early.
function run(stores, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    let result;
    const req = fn(t);
    if (req && 'onsuccess' in req) req.onsuccess = () => { result = req.result; };
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('Storage operation was aborted'));
  });
}
const idb = {
  get: (s, k) => run(s, 'readonly', t => t.objectStore(s).get(k)),
  getAll: s => run(s, 'readonly', t => t.objectStore(s).getAll()),
  has: (s, k) => run(s, 'readonly', t => t.objectStore(s).getKey(k)).then(r => r !== undefined),
  put: (s, v, k) => run(s, 'readwrite', t => k === undefined ? t.objectStore(s).put(v) : t.objectStore(s).put(v, k)),
};

// ---------------------------------------------------------------- crypto
async function deriveKEK(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
async function wrapDEK(key, password) {
  const salt = rand(16), iv = rand(12);
  const kek = await deriveKEK(password, salt, KDF_ITER);
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', key, kek, { name: 'AES-GCM', iv }));
  return { v: 1, kdf: 'PBKDF2-SHA256', iter: KDF_ITER, salt, iv, wrapped };
}
// Returns the data key, or null if the password is wrong (GCM authentication fails).
async function unwrapDEK(vault, password) {
  const kek = await deriveKEK(password, vault.salt, vault.iter);
  try {
    return await crypto.subtle.unwrapKey('raw', vault.wrapped, kek, { name: 'AES-GCM', iv: vault.iv },
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  } catch {
    return null;
  }
}
async function seal(key, bytes, aad) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, bytes);
  return { iv, ct: new Uint8Array(ct) };
}
async function unseal(key, rec, aad) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: rec.iv, additionalData: te.encode(aad) }, key, rec.ct));
}
const sealJSON = (key, obj, aad) => seal(key, te.encode(JSON.stringify(obj)), aad);
const unsealJSON = async (key, rec, aad) => JSON.parse(td.decode(await unseal(key, rec, aad)));
async function sameKey(a, b) {
  const [x, y] = await Promise.all([a, b].map(k => crypto.subtle.exportKey('raw', k).then(r => new Uint8Array(r))));
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

// ---------------------------------------------------------------- UI feedback
function busy(msg) {
  $('#busy-msg').textContent = msg || 'Working…';
  const dlg = $('#busy');
  if (!dlg.open) dlg.showModal();
}
function idle() { const dlg = $('#busy'); if (dlg.open) dlg.close(); }
async function withBusy(msg, fn) {
  busy(msg);
  // Let the overlay paint before heavy work starts.
  await new Promise(r => setTimeout(r, 30));
  try { return await fn(); } finally { idle(); }
}
let toastTimer;
function toast(msg, ms = 2800) {
  const t = $('#toast');
  t.textContent = msg;
  if (t.showPopover) { try { t.hidePopover(); } catch {} t.showPopover(); } else t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { if (t.hidePopover) { try { t.hidePopover(); } catch {} } else t.hidden = true; }, ms);
}
function fail(err) {
  console.error(err);
  const quota = err && (err.name === 'QuotaExceededError' || /quota/i.test(err.message || ''));
  toast('⚠️ ' + (quota ? 'This device is out of storage space for Doc Vault.' : (err && err.message) || String(err)), 6000);
}

// A small modal for passwords and confirmations. `check` runs before closing and
// returns an error message to keep the dialog open, or nothing to accept.
function ask({ title, message = '', fields = [], ok = 'OK', danger = false, check }) {
  const dlg = $('#dlg-prompt');
  const form = $('#prompt-form');
  const okBtn = $('#prompt-ok');
  const err = $('#prompt-error');
  $('#prompt-title').textContent = title;
  $('#prompt-msg').textContent = message;
  $('#prompt-msg').hidden = !message;
  $('#prompt-fields').innerHTML = fields.map((f, i) =>
    `<label>${esc(f.label)}<input name="f${i}" type="${f.type || 'text'}" autocomplete="off" required></label>`).join('');
  err.hidden = true;
  okBtn.textContent = ok;
  okBtn.className = 'btn ' + (danger ? 'danger' : 'primary');
  okBtn.disabled = false;
  return new Promise(resolve => {
    const done = val => {
      form.onsubmit = null; $('#prompt-cancel').onclick = null; dlg.onclose = null;
      if (dlg.open) dlg.close();
      resolve(val);
    };
    form.onsubmit = async e => {
      e.preventDefault();
      const values = fields.map((_, i) => form.elements['f' + i].value);
      if (check) {
        okBtn.disabled = true; okBtn.textContent = 'Checking…';
        let problem;
        try { problem = await check(values); } catch (x) { problem = x.message || String(x); }
        okBtn.disabled = false; okBtn.textContent = ok;
        if (problem) { err.textContent = problem; err.hidden = false; return; }
      }
      done(values);
    };
    $('#prompt-cancel').onclick = () => done(null);
    // 'close' is delivered asynchronously; ignore a stale one if the dialog was reopened since.
    dlg.onclose = () => { if (!dlg.open) done(null); };
    dlg.showModal();
    const first = $('#prompt-fields input');
    (first || okBtn).focus();
  });
}
const confirmAction = (title, message, ok = 'OK', danger = false) =>
  ask({ title, message, ok, danger }).then(v => v !== null);

// ---------------------------------------------------------------- screens & locking
function showScreen(name) {
  for (const s of ['setup', 'lock', 'main']) $('#screen-' + s).hidden = s !== name;
  const focus = { setup: '#setup-pw', lock: '#lock-pw' }[name];
  if (focus) setTimeout(() => $(focus).focus(), 60);
}

async function enterVault() {
  await withBusy('Decrypting…', loadVault);
  showScreen('main');
  render();
  lastActive = Date.now();
  // Ask the browser never to evict our data when storage runs low.
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
}

async function loadVault() {
  const s = await idb.get('meta', 'settings');
  settings = { ...DEFAULT_SETTINGS, ...(s ? await unsealJSON(dek, s, 'settings') : {}) };
  docs.clear();
  for (const rec of await idb.getAll('docs')) {
    try { docs.set(rec.id, await unsealJSON(dek, rec, rec.id)); }
    catch { console.warn('Skipping unreadable record', rec.id); }
  }
}

async function saveSettings() {
  await idb.put('meta', await sealJSON(dek, settings, 'settings'), 'settings');
}

function lock() {
  if (!dek) return;
  dek = null;
  docs.clear();
  if (editing) editing.urls.forEach(u => URL.revokeObjectURL(u));
  editing = null;
  viewingId = null;
  closeImage();
  for (const u of thumbUrls.values()) URL.revokeObjectURL(u);
  thumbUrls.clear();
  $$('dialog[open]').forEach(d => d.close());
  $('#grid').innerHTML = '';
  $('#search').value = '';
  filter = { cat: 'all', member: 'all', q: '' };
  showScreen('lock');
}

function checkIdle() {
  if (!dek || $('#busy').open) return;
  if (Date.now() - pickingSince < 10 * 60000) return;
  if (Date.now() - lastActive > settings.autolock * 60000) lock();
}

// ---------------------------------------------------------------- data operations
function liveDocs() { return [...docs.values()].filter(d => !d.deleted); }

async function thumbURL(fileId) {
  if (thumbUrls.has(fileId)) return thumbUrls.get(fileId);
  const rec = await idb.get('thumbs', fileId);
  if (!rec || !dek) return null;
  const url = URL.createObjectURL(new Blob([await unseal(dek, rec, 't:' + fileId)], { type: 'image/jpeg' }));
  thumbUrls.set(fileId, url);
  return url;
}
function dropThumb(fileId) {
  const u = thumbUrls.get(fileId);
  if (u) { URL.revokeObjectURL(u); thumbUrls.delete(fileId); }
}
function hydrateThumbs(root) {
  for (const img of $$('img[data-thumb]', root)) {
    thumbURL(img.dataset.thumb).then(u => { if (u) img.src = u; }).catch(() => {});
  }
}
async function loadFileBlob(f) {
  const rec = await idb.get('files', f.id);
  if (!rec) throw new Error(`The data for "${f.name}" is missing.`);
  return new Blob([await unseal(dek, rec, f.id)], { type: f.type });
}

function canvasJpeg(bmp, max, quality) {
  const r = Math.min(1, max / Math.max(bmp.width, bmp.height));
  const c = document.createElement('canvas');
  c.width = Math.max(1, Math.round(bmp.width * r));
  c.height = Math.max(1, Math.round(bmp.height * r));
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#fff';                     // transparent PNGs become white, not black
  ctx.fillRect(0, 0, c.width, c.height);
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(bmp, 0, 0, c.width, c.height);
  return new Promise(res => c.toBlob(res, 'image/jpeg', quality));
}

// Turns a picked file into an attachment: optionally shrinks big photos and makes a thumbnail.
async function prepareFile(file) {
  let blob = file;
  let type = file.type || (/\.pdf$/i.test(file.name) ? 'application/pdf' : 'application/octet-stream');
  let name = file.name || `photo-${Date.now()}.jpg`;
  let thumbBlob = null;
  if (type.startsWith('image/')) {
    let bmp = null;
    try { bmp = await createImageBitmap(file); } catch { /* format the browser can't draw (e.g. HEIC): stored as-is */ }
    if (bmp) {
      const big = Math.max(bmp.width, bmp.height) > MAX_DIM || file.size > 1.5e6;
      if (settings.compress && big && type !== 'image/gif') {
        const small = await canvasJpeg(bmp, MAX_DIM, 0.88);
        if (small && small.size < file.size) {
          blob = small;
          type = 'image/jpeg';
          name = name.replace(/\.[^.]*$/, '') + '.jpg';
        }
      }
      thumbBlob = await canvasJpeg(bmp, THUMB_DIM, 0.72);
      bmp.close();
    }
  }
  return { id: uid(), name, type, size: blob.size, thumb: !!thumbBlob, blob, thumbBlob, isNew: true };
}

// ---------------------------------------------------------------- main list
function matches(d) {
  if (filter.cat === 'fav' && !d.fav) return false;
  if (filter.cat === 'exp' && !expiryState(d)) return false;
  if (filter.cat.startsWith('c:') && d.category !== filter.cat.slice(2)) return false;
  if (filter.member !== 'all' && d.member !== filter.member) return false;
  const words = filter.q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [d.title, d.category, d.member, d.number, (d.number || '').replace(/[\s-]/g, ''),
    d.notes, ...(d.tags || []), ...d.files.map(f => f.name)].join(' ').toLowerCase();
  return words.every(w => hay.includes(w));
}
const byImportanceThenTitle = (a, b) => (!!b.fav - !!a.fav) || a.title.localeCompare(b.title);
function categoryRank(c) { const i = CATEGORY_ORDER.indexOf(c); return i < 0 ? CATEGORY_ORDER.length - 1 : i; }

function cardHTML(d) {
  const st = expiryState(d);
  const first = d.files.find(f => f.thumb);
  const n = d.files.length;
  const placeholder = n && isPdf(d.files[0]) ? '📄' : catIcon(d.category);
  const sub = [d.member, d.number && maskNumber(d.number)].filter(Boolean).join(' · ');
  return `<article class="card" data-id="${esc(d.id)}" tabindex="0" role="button" aria-label="${esc(d.title)}">
    <div class="thumb">${first ? `<img data-thumb="${esc(first.id)}" alt="">` : `<span>${placeholder}</span>`}
      ${d.fav ? '<span class="fav">⭐</span>' : ''}${n > 1 ? `<span class="pages">${n} files</span>` : ''}</div>
    <div class="meta"><div class="title">${esc(d.title)}</div><div class="sub">${esc(sub) || '&nbsp;'}</div>
      ${st ? `<span class="badge ${st.cls}">${esc(st.text)}</span>` : ''}</div>
  </article>`;
}

function render() {
  if (!dek) return;
  const all = liveDocs();

  // Category chips (only categories in use, plus smart filters).
  const counts = new Map();
  for (const d of all) counts.set(d.category, (counts.get(d.category) || 0) + 1);
  const expiring = all.filter(expiryState).length;
  const chips = [
    ['all', 'All', all.length],
    ['fav', '⭐ Important', all.filter(d => d.fav).length],
    ['exp', '⏰ Expiring', expiring],
    ...[...counts].sort((a, b) => categoryRank(a[0]) - categoryRank(b[0]) || a[0].localeCompare(b[0]))
      .map(([c, n]) => ['c:' + c, `${catIcon(c)} ${c}`, n]),
  ].filter(([k, , n]) => k === 'all' || n > 0 || filter.cat === k);
  if (!chips.some(([k]) => k === filter.cat)) filter.cat = 'all';
  $('#chips').innerHTML = chips.map(([k, label, n]) =>
    `<button class="chip${filter.cat === k ? ' active' : ''}" data-cat="${esc(k)}">${esc(label)}<span class="count">${n}</span></button>`).join('');

  // Person filter, shown once there is more than one person.
  const members = [...new Set(all.map(d => d.member).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  if (filter.member !== 'all' && !members.includes(filter.member)) filter.member = 'all';
  $('#member-filter').innerHTML = `<option value="all">All people</option>` +
    members.map(m => `<option value="${esc(m)}"${m === filter.member ? ' selected' : ''}>${esc(m)}</option>`).join('');
  $('#member-filter').hidden = members.length < 2;

  // Reminder bar: expiring documents first, then a stale-backup nudge.
  const bar = $('#alert-bar');
  const backupAge = settings.lastBackup ? (Date.now() - settings.lastBackup) / 864e5 : Infinity;
  if (expiring && filter.cat !== 'exp') {
    bar.textContent = `⏰ ${expiring} document${expiring > 1 ? 's have' : ' has'} expired or expire${expiring > 1 ? '' : 's'} within ${EXPIRY_WARN_DAYS} days. Tap to see.`;
    bar.dataset.action = 'expiring';
    bar.hidden = false;
  } else if (all.length && backupAge > BACKUP_NAG_DAYS) {
    bar.textContent = settings.lastBackup
      ? `💾 Last backup was ${Math.floor(backupAge)} days ago. Tap to back up.`
      : '💾 You have no backup yet. If this device is lost, so are your documents. Tap to back up.';
    bar.dataset.action = 'backup';
    bar.hidden = false;
  } else bar.hidden = true;

  // Cards: grouped by category in the "All" view, flat otherwise.
  const list = all.filter(matches).sort(byImportanceThenTitle);
  $('#empty').hidden = all.length > 0;
  const grid = $('#grid');
  if (!all.length) grid.innerHTML = '';
  else if (!list.length) grid.innerHTML = '<p class="muted no-match">No documents match your search.</p>';
  else if (filter.cat === 'all' && !filter.q) {
    const groups = new Map();
    for (const d of list) { if (!groups.has(d.category)) groups.set(d.category, []); groups.get(d.category).push(d); }
    grid.innerHTML = [...groups].sort((a, b) => categoryRank(a[0]) - categoryRank(b[0]) || a[0].localeCompare(b[0]))
      .map(([c, items]) => `<h3 class="group-head">${catIcon(c)} ${esc(c)} <span class="count">${items.length}</span></h3>
        <div class="grid">${items.map(cardHTML).join('')}</div>`).join('');
  } else grid.innerHTML = `<div class="grid">${list.map(cardHTML).join('')}</div>`;
  hydrateThumbs(grid);
}

// ---------------------------------------------------------------- add / edit
function fillDatalists() {
  const all = liveDocs();
  const cats = [...new Set([...CATEGORY_ORDER, ...all.map(d => d.category)])];
  const members = [...new Set(['Self', ...all.map(d => d.member).filter(Boolean)])];
  $('#dl-categories').innerHTML = cats.map(c => `<option value="${esc(c)}">`).join('');
  $('#dl-members').innerHTML = members.map(m => `<option value="${esc(m)}">`).join('');
}

function openEditor(id, { fromView = false } = {}) {
  const d = id ? docs.get(id) : null;
  editing = {
    id: d ? d.id : uid(),
    created: d ? d.created : Date.now(),
    files: d ? d.files.map(f => ({ ...f })) : [],
    removed: [],
    urls: [],
    dirty: false,
    fromView,
  };
  $('#edit-title').textContent = d ? 'Edit document' : 'Add document';
  $('#f-title').value = d ? d.title : '';
  $('#f-category').value = d ? d.category : (filter.cat.startsWith('c:') ? filter.cat.slice(2) : '');
  $('#f-member').value = d ? d.member : (filter.member !== 'all' ? filter.member : '');
  $('#f-number').value = d ? d.number || '' : '';
  $('#f-issue').value = d ? d.issue || '' : '';
  $('#f-expiry').value = d ? d.expiry || '' : '';
  $('#f-tags').value = d ? (d.tags || []).join(', ') : '';
  $('#f-notes').value = d ? d.notes || '' : '';
  $('#f-fav').checked = d ? !!d.fav : false;
  const used = new Set(liveDocs().map(x => x.title.toLowerCase()));
  $('#quick').innerHTML = d ? '' : QUICK_TEMPLATES.filter(([t]) => !used.has(t.toLowerCase()))
    .map(([t, c]) => `<button type="button" class="chip" data-title="${esc(t)}" data-cat="${esc(c)}">${catIcon(c)} ${esc(t)}</button>`).join('');
  fillDatalists();
  renderEditFiles();
  $('#dlg-edit').showModal();
  $('#dlg-edit .sheet-body').scrollTop = 0;
}

function renderEditFiles() {
  const box = $('#edit-files');
  box.innerHTML = editing.files.map((f, i) => `<div class="attach-item">
      ${f.thumb ? `<img alt="" data-fid="${esc(f.id)}">` : `<span class="pdf">${isPdf(f) ? '📄' : '🖼️'}</span>`}
      <span class="fname">${esc(f.name)}</span>
      <button type="button" class="rm" data-rm="${i}" aria-label="Remove ${esc(f.name)}">✕</button>
      ${i > 0 ? `<button type="button" class="mv" data-mv="${i}" aria-label="Move earlier">◀</button>` : ''}
    </div>`).join('');
  for (const img of $$('img[data-fid]', box)) {
    const f = editing.files.find(x => x.id === img.dataset.fid);
    if (f.thumbBlob) {
      const u = URL.createObjectURL(f.thumbBlob);
      editing.urls.push(u);
      img.src = u;
    } else thumbURL(f.id).then(u => { if (u) img.src = u; }).catch(() => {});
  }
}

async function addFiles(fileList) {
  if (!editing) return;
  const files = [...fileList];
  if (!files.length) return;
  try {
    await withBusy(`Preparing ${files.length} file${files.length > 1 ? 's' : ''}…`, async () => {
      for (const f of files) {
        if (!/^image\//.test(f.type) && f.type !== 'application/pdf' && !/\.pdf$/i.test(f.name)) {
          toast(`Skipped "${f.name}": only photos and PDFs can be added.`);
          continue;
        }
        if (!editing) return;                  // vault locked meanwhile
        editing.files.push(await prepareFile(f));
        editing.dirty = true;
      }
    });
  } catch (err) { fail(err); }
  if (editing) renderEditFiles();
}

async function saveEditor() {
  const ed = editing;
  const title = $('#f-title').value.trim();
  if (!title) { $('#f-title').focus(); return; }
  const meta = {
    id: ed.id,
    title,
    category: $('#f-category').value.trim() || 'Other',
    member: $('#f-member').value.trim() || 'Self',
    number: $('#f-number').value.trim(),
    issue: $('#f-issue').value,
    expiry: $('#f-expiry').value,
    tags: $('#f-tags').value.split(',').map(t => t.trim()).filter(Boolean),
    notes: $('#f-notes').value.trim(),
    fav: $('#f-fav').checked,
    files: ed.files.map(({ id, name, type, size, thumb }) => ({ id, name, type, size, thumb })),
    created: ed.created,
    updated: Date.now(),
  };
  try {
    await withBusy('Encrypting & saving…', async () => {
      // Encrypt everything first, then write it all in one atomic transaction.
      const fileRecs = [], thumbRecs = [];
      for (const f of ed.files.filter(x => x.isNew)) {
        fileRecs.push({ id: f.id, docId: meta.id, ...await seal(dek, new Uint8Array(await f.blob.arrayBuffer()), f.id) });
        if (f.thumbBlob) thumbRecs.push({ id: f.id, ...await seal(dek, new Uint8Array(await f.thumbBlob.arrayBuffer()), 't:' + f.id) });
      }
      const docRec = { id: meta.id, ...await sealJSON(dek, meta, meta.id) };
      await run(['docs', 'files', 'thumbs'], 'readwrite', t => {
        for (const r of fileRecs) t.objectStore('files').put(r);
        for (const r of thumbRecs) t.objectStore('thumbs').put(r);
        for (const fid of ed.removed) { t.objectStore('files').delete(fid); t.objectStore('thumbs').delete(fid); }
        t.objectStore('docs').put(docRec);
      });
    });
  } catch (err) { return fail(err); }
  ed.removed.forEach(dropThumb);
  docs.set(meta.id, meta);
  ed.dirty = false;
  $('#dlg-edit').close();
  render();
  toast(`Saved "${meta.title}" 🔒`);
  if (ed.fromView) openView(meta.id);
}

async function closeEditor() {
  if (editing && editing.dirty && !await confirmAction('Discard changes?', 'Your changes to this document have not been saved.', 'Discard', true)) return;
  $('#dlg-edit').close();
}

// ---------------------------------------------------------------- view
function openView(id) {
  const d = docs.get(id);
  if (!d || d.deleted) return;
  viewingId = id;
  $('#view-title').textContent = d.title;
  const files = $('#view-files');
  files.innerHTML = d.files.length ? d.files.map(f => `<button type="button" class="view-file" data-fid="${esc(f.id)}">
      <div class="vf-thumb">${f.thumb ? `<img alt="" data-thumb="${esc(f.id)}">` : (isPdf(f) ? '📄' : '🖼️')}</div>
      <div class="vf-name">${esc(f.name)} · ${fmtSize(f.size)}</div></button>`).join('')
    : '<p class="muted">No files attached. Tap Edit to add photos or PDFs.</p>';
  hydrateThumbs(files);
  const st = expiryState(d);
  const rows = [
    ['Category', `${catIcon(d.category)} ${d.category}`],
    ['Belongs to', d.member],
    ['Number', d.number, true],
    ['Issued', fmtDate(d.issue)],
    ['Expires', d.expiry && fmtDate(d.expiry) + (st ? ` (${st.text})` : '')],
    ['Tags', (d.tags || []).join(', ')],
    ['Notes', d.notes],
    ['Added', fmtDateTime(d.created)],
    ['Updated', fmtDateTime(d.updated)],
  ].filter(r => r[1]);
  $('#view-details').innerHTML = rows.map(([k, v, copy]) =>
    `<dt>${k}</dt><dd>${esc(v)}${copy ? ` <button type="button" class="copy" data-copy="${esc(v)}">Copy</button>` : ''}</dd>`).join('');
  const dlg = $('#dlg-view');
  if (!dlg.open) dlg.showModal();
}

async function openFile(fileId) {
  const d = docs.get(viewingId);
  const f = d && d.files.find(x => x.id === fileId);
  if (!f) return;
  if (isViewableImage(f)) {
    const images = d.files.filter(isViewableImage);
    return showImage(images, images.indexOf(f));
  }
  try {
    const blob = await withBusy('Decrypting…', () => loadFileBlob(f));
    if (isTouch()) await saveOrShare(blob, f.name);
    else {
      const url = URL.createObjectURL(blob);
      const w = window.open(url, '_blank');
      setTimeout(() => URL.revokeObjectURL(url), 5 * 60000);
      if (!w) download(blob, f.name);
    }
  } catch (err) { fail(err); }
}

async function showImage(files, index) {
  if (index < 0 || index >= files.length) return;
  let blob;
  try {
    blob = await withBusy('Decrypting…', () => loadFileBlob(files[index]));
  } catch (err) { return fail(err); }
  if (imageView) URL.revokeObjectURL(imageView.url);
  imageView = { files, index, blob, url: URL.createObjectURL(blob) };
  $('#img-el').src = imageView.url;
  $('#img-name').textContent = `${files[index].name}${files.length > 1 ? `  (${index + 1}/${files.length})` : ''}`;
  $('#img-prev').hidden = $('#img-next').hidden = files.length < 2;
  $('#img-prev').disabled = index === 0;
  $('#img-next').disabled = index === files.length - 1;
  $('#img-body').classList.remove('zoomed');
  const dlg = $('#dlg-image');
  if (!dlg.open) dlg.showModal();
}
function closeImage() {
  if (imageView) URL.revokeObjectURL(imageView.url);
  imageView = null;
  $('#img-el').removeAttribute('src');
}

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
async function saveOrShare(blob, name) {
  const file = new File([blob], name, { type: blob.type });
  if (isTouch() && navigator.canShare && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file], title: name }); return; }
    catch (e) { if (e.name === 'AbortError') return; }
  }
  download(blob, name);
  toast('Saved a normal (unencrypted) copy to your Downloads.', 4000);
}

async function deleteViewed() {
  const d = docs.get(viewingId);
  if (!d) return;
  const n = d.files.length;
  if (!await confirmAction('Delete this document?',
    `"${d.title}"${n ? ` and its ${n} file${n > 1 ? 's' : ''}` : ''} will be permanently removed from this device.`, 'Delete', true)) return;
  // Keep a small encrypted "tombstone" so that merging an older backup doesn't bring it back.
  const tomb = { id: d.id, deleted: true, title: '', files: [], created: d.created, updated: Date.now() };
  try {
    const rec = { id: d.id, ...await sealJSON(dek, tomb, d.id) };
    await run(['docs', 'files', 'thumbs'], 'readwrite', t => {
      for (const f of d.files) { t.objectStore('files').delete(f.id); t.objectStore('thumbs').delete(f.id); }
      t.objectStore('docs').put(rec);
    });
  } catch (err) { return fail(err); }
  d.files.forEach(f => dropThumb(f.id));
  docs.set(d.id, tomb);
  $('#dlg-view').close();
  render();
  toast('Deleted');
}

// ---------------------------------------------------------------- settings
async function openSettings() {
  $('#set-autolock').value = String(settings.autolock);
  $('#set-lockhide').checked = settings.lockOnHide;
  $('#set-compress').checked = settings.compress;
  $('#last-backup').textContent = settings.lastBackup
    ? `Last backup: ${fmtDateTime(settings.lastBackup)}`
    : 'No backup yet. Make one and keep it somewhere safe, like a pen drive or your PC.';
  $('#dlg-settings').showModal();
  const all = liveDocs();
  const files = all.reduce((n, d) => n + d.files.length, 0);
  let text = `${all.length} document${all.length === 1 ? '' : 's'} · ${files} file${files === 1 ? '' : 's'}`;
  try {
    if (navigator.storage && navigator.storage.estimate) {
      const { usage, quota } = await navigator.storage.estimate();
      text += ` · ${fmtSize(usage)} used, about ${fmtSize(quota)} available`;
    }
    if (navigator.storage && navigator.storage.persisted) {
      text += (await navigator.storage.persisted())
        ? '. 🔐 Protected from automatic browser clean-up.'
        : '. ⚠️ Not yet protected from browser clean-up when space runs low, so keep backups. (Installing the app usually fixes this.)';
    }
  } catch {}
  $('#storage-info').textContent = text;
}

async function changePassword() {
  const vault = await idb.get('meta', 'vault');
  const vals = await ask({
    title: 'Change master password',
    fields: [
      { label: 'Current password', type: 'password' },
      { label: 'New password (at least 8 characters)', type: 'password' },
      { label: 'Confirm new password', type: 'password' },
    ],
    ok: 'Change',
    check: async ([cur, n1, n2]) => {
      if (n1.length < 8) return 'The new password must have at least 8 characters.';
      if (n1 !== n2) return 'The new passwords do not match.';
      return (await unwrapDEK(vault, cur)) ? '' : 'The current password is wrong.';
    },
  });
  if (!vals) return;
  try {
    await withBusy('Re-securing vault…', async () => idb.put('meta', await wrapDEK(dek, vals[1]), 'vault'));
    toast('Password changed. Backups made earlier still open with the old password.', 5000);
  } catch (err) { fail(err); }
}

async function wipeVault() {
  const ok = await ask({
    title: 'Erase everything on this device?',
    message: 'All documents in Doc Vault on THIS device will be permanently deleted. Backup files are not affected. Type ERASE to confirm.',
    fields: [{ label: 'Type ERASE' }],
    ok: 'Erase',
    danger: true,
    check: async ([t]) => t.trim().toUpperCase() === 'ERASE' ? '' : 'Type ERASE to confirm.',
  });
  if (!ok) return;
  lock();
  db.close();
  const req = indexedDB.deleteDatabase(DB_NAME);
  req.onsuccess = req.onerror = req.onblocked = () => location.reload();
}

// ---------------------------------------------------------------- backup & restore
async function exportBackup() {
  try {
    await withBusy('Packing encrypted backup…', async () => {
      const [vault, sett, docRecs, fileRecs, thumbRecs] = await Promise.all([
        idb.get('meta', 'vault'), idb.get('meta', 'settings'),
        idb.getAll('docs'), idb.getAll('files'), idb.getAll('thumbs'),
      ]);
      // Built from many small strings so very large vaults don't need one giant string.
      const parts = [`{"app":"DocVault","format":1,"exported":${Date.now()},"vault":${JSON.stringify(pack(vault))}`];
      if (sett) parts.push(`,"settings":${JSON.stringify(pack(sett))}`);
      for (const [name, recs] of [['docs', docRecs], ['files', fileRecs], ['thumbs', thumbRecs]]) {
        parts.push(`,"${name}":[`);
        recs.forEach((r, i) => parts.push((i ? ',' : '') + JSON.stringify(pack(r))));
        parts.push(']');
      }
      parts.push('}');
      const day = new Date().toISOString().slice(0, 10);
      download(new Blob(parts, { type: 'application/octet-stream' }), `Vedants-Doc-Vault-backup-${day}.vault`);
    });
    settings.lastBackup = Date.now();
    await saveSettings();
    render();
    $('#last-backup').textContent = `Last backup: ${fmtDateTime(settings.lastBackup)}`;
    toast('Backup saved to Downloads. Copy it to your other device or a pen drive.', 5000);
  } catch (err) { fail(err); }
}

function pickBackup(mode) {
  backupMode = mode;
  pickingSince = Date.now();
  $('#in-backup').value = '';
  $('#in-backup').click();
}

async function importBackup(file) {
  if (backupMode === 'merge' && !dek) return;   // locked while the picker was open
  let data;
  try {
    data = await withBusy('Reading backup…', async () => JSON.parse(await file.text()));
  } catch { return toast('That file is not a Doc Vault backup.', 4000); }
  // "DocVault" is the backup format's fixed identifier, not the display name.
  if (!data || data.app !== 'DocVault' || !data.vault || !Array.isArray(data.docs)) {
    return toast('That file is not a Doc Vault backup.', 4000);
  }
  const bvault = unpack(data.vault);
  let bkey = null;
  const answer = await ask({
    title: 'Backup password',
    message: `Backup from ${fmtDateTime(data.exported)}. Enter the master password that was in use when it was made.`,
    fields: [{ label: 'Password', type: 'password' }],
    ok: 'Open backup',
    check: async ([p]) => { bkey = await unwrapDEK(bvault, p); return bkey ? '' : 'Wrong password for this backup.'; },
  });
  if (!answer) return;

  try {
    if (backupMode === 'restore') await restoreInto(data, bvault, bkey);
    else await mergeFrom(data, bkey);
  } catch (err) { fail(err); }
}

// Fresh device: adopt the backup as-is (same key, same password).
async function restoreInto(data, bvault, bkey) {
  await withBusy('Restoring…', () => run(['meta', 'docs', 'files', 'thumbs'], 'readwrite', t => {
    t.objectStore('meta').put(bvault, 'vault');
    if (data.settings) t.objectStore('meta').put(unpack(data.settings), 'settings');
    for (const r of data.docs) t.objectStore('docs').put(unpack(r));
    for (const r of data.files || []) t.objectStore('files').put(unpack(r));
    for (const r of data.thumbs || []) t.objectStore('thumbs').put(unpack(r));
  }));
  dek = bkey;
  await enterVault();
  toast(`Restored ${liveDocs().length} documents.`, 4000);
}

// Existing vault: newest version of each document wins; deletions carry over.
async function mergeFrom(data, bkey) {
  const same = await sameKey(dek, bkey);
  const bFiles = new Map((data.files || []).map(r => [r.id, r]));
  const bThumbs = new Map((data.thumbs || []).map(r => [r.id, r]));
  let added = 0, updated = 0, removed = 0, skipped = 0;
  busy('Merging…');
  try {
    for (let i = 0; i < data.docs.length; i++) {
      $('#busy-msg').textContent = `Merging ${i + 1} of ${data.docs.length}…`;
      const rec = unpack(data.docs[i]);
      let meta;
      try { meta = await unsealJSON(bkey, rec, rec.id); } catch { skipped++; continue; }
      const local = docs.get(meta.id);
      if (local && local.updated >= meta.updated) continue;

      const fileRecs = [], thumbRecs = [];
      const drop = local ? local.files.filter(f => !meta.files.some(x => x.id === f.id)).map(f => f.id) : [];
      for (const f of meta.files) {
        if (await idb.has('files', f.id)) continue;          // file contents never change once stored
        const fr = bFiles.get(f.id);
        if (!fr) continue;
        const raw = unpack(fr);
        fileRecs.push(same ? raw : { id: f.id, docId: meta.id, ...await seal(dek, await unseal(bkey, raw, f.id), f.id) });
        const tr = bThumbs.get(f.id);
        if (tr) {
          const traw = unpack(tr);
          thumbRecs.push(same ? traw : { id: f.id, ...await seal(dek, await unseal(bkey, traw, 't:' + f.id), 't:' + f.id) });
        }
      }
      const docRec = same ? rec : { id: meta.id, ...await sealJSON(dek, meta, meta.id) };
      await run(['docs', 'files', 'thumbs'], 'readwrite', t => {
        for (const r of fileRecs) t.objectStore('files').put(r);
        for (const r of thumbRecs) t.objectStore('thumbs').put(r);
        for (const fid of drop) { t.objectStore('files').delete(fid); t.objectStore('thumbs').delete(fid); }
        t.objectStore('docs').put(docRec);
      });
      drop.forEach(dropThumb);
      docs.set(meta.id, meta);
      if (meta.deleted) { if (local && !local.deleted) removed++; }
      else if (local && !local.deleted) updated++;
      else added++;
    }
  } finally { idle(); }
  render();
  const parts = [`${added} added`, `${updated} updated`];
  if (removed) parts.push(`${removed} removed`);
  if (skipped) parts.push(`${skipped} unreadable`);
  toast(`Backup merged: ${parts.join(', ')}.`, 5000);
}

// ---------------------------------------------------------------- event wiring
function wire() {
  // Setup
  $('#setup-form').addEventListener('submit', async e => {
    e.preventDefault();
    const pw = $('#setup-pw').value, pw2 = $('#setup-pw2').value;
    if (pw.length < 8) return toast('Use at least 8 characters.');
    if (pw !== pw2) return toast('The passwords do not match.');
    try {
      await withBusy('Creating encrypted vault…', async () => {
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        await idb.put('meta', await wrapDEK(key, pw), 'vault');
        dek = key;
        settings = { ...DEFAULT_SETTINGS };
        await saveSettings();
      });
    } catch (err) { return fail(err); }
    $('#setup-form').reset();
    await enterVault();
  });
  $('#setup-restore').addEventListener('click', () => pickBackup('restore'));

  // Unlock
  let failures = 0;
  $('#lock-form').addEventListener('submit', async e => {
    e.preventDefault();
    const pw = $('#lock-pw').value;
    const vault = await idb.get('meta', 'vault');
    const key = await withBusy('Unlocking…', async () => {
      const k = await unwrapDEK(vault, pw);
      // Growing delay after repeated wrong guesses.
      if (!k && ++failures > 3) await new Promise(r => setTimeout(r, Math.min(30, 2 ** (failures - 3)) * 1000));
      return k;
    });
    if (!key) { $('#lock-error').hidden = false; $('#lock-pw').select(); return; }
    failures = 0;
    $('#lock-error').hidden = true;
    $('#lock-form').reset();
    dek = key;
    try { await enterVault(); } catch (err) { dek = null; fail(err); }
  });

  // Main screen
  $('#btn-lock').addEventListener('click', lock);
  $('#btn-add').addEventListener('click', () => openEditor());
  $('#btn-settings').addEventListener('click', openSettings);
  $('#search').addEventListener('input', e => { filter.q = e.target.value.trim(); render(); });
  $('#member-filter').addEventListener('change', e => { filter.member = e.target.value; render(); });
  $('#chips').addEventListener('click', e => {
    const chip = e.target.closest('[data-cat]');
    if (chip) { filter.cat = chip.dataset.cat; render(); }
  });
  $('#alert-bar').addEventListener('click', e => {
    if (e.currentTarget.dataset.action === 'backup') openSettings();
    else { filter.cat = 'exp'; render(); }
  });
  $('#grid').addEventListener('click', e => {
    const card = e.target.closest('.card');
    if (card) openView(card.dataset.id);
  });
  $('#grid').addEventListener('keydown', e => {
    const card = e.target.closest('.card');
    if (card && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openView(card.dataset.id); }
  });

  // Close buttons on every dialog
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-close]');
    if (!btn) return;
    const dlg = btn.closest('dialog');
    if (dlg.id === 'dlg-edit') closeEditor(); else dlg.close();
  });

  // Editor
  const editDlg = $('#dlg-edit');
  editDlg.addEventListener('cancel', e => { e.preventDefault(); closeEditor(); });
  editDlg.addEventListener('close', () => {
    if (editDlg.open) return;                  // stale event: the editor was reopened already
    if (editing) editing.urls.forEach(u => URL.revokeObjectURL(u));
    editing = null;
    $('#edit-files').innerHTML = '';
  });
  $('#edit-form').addEventListener('submit', e => { e.preventDefault(); saveEditor(); });
  $('#edit-form').addEventListener('input', () => { if (editing) editing.dirty = true; });
  for (const id of ['#in-camera', '#in-files']) {
    const input = $(id);
    input.addEventListener('click', () => { pickingSince = Date.now(); });
    input.addEventListener('cancel', () => { pickingSince = 0; });
    input.addEventListener('change', async () => {
      pickingSince = 0;
      lastActive = Date.now();
      const files = [...input.files];
      input.value = '';
      await addFiles(files);
    });
  }
  $('#edit-files').addEventListener('click', e => {
    const rm = e.target.closest('[data-rm]');
    const mv = e.target.closest('[data-mv]');
    if (rm) {
      const [f] = editing.files.splice(+rm.dataset.rm, 1);
      if (!f.isNew) editing.removed.push(f.id);
    } else if (mv) {
      const i = +mv.dataset.mv;
      [editing.files[i - 1], editing.files[i]] = [editing.files[i], editing.files[i - 1]];
    } else return;
    editing.dirty = true;
    renderEditFiles();
  });
  $('#quick').addEventListener('click', e => {
    const q = e.target.closest('[data-title]');
    if (!q) return;
    $('#f-title').value = q.dataset.title;
    $('#f-category').value = q.dataset.cat;
    editing.dirty = true;
    $('#quick').innerHTML = '';
  });
  // Drag & drop and paste (PC)
  const zone = $('.attach-zone');
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('drag'); addFiles(e.dataTransfer.files); });
  document.addEventListener('dragover', e => { if (dek) e.preventDefault(); });
  document.addEventListener('drop', e => {
    if (!dek || !e.dataTransfer || !e.dataTransfer.files.length) return;
    e.preventDefault();
    if (!editing) { if ($$('dialog[open]').length) return; openEditor(); }
    addFiles(e.dataTransfer.files);
  });
  document.addEventListener('paste', e => {
    if (!editing || !e.clipboardData || !e.clipboardData.files.length) return;
    e.preventDefault();
    addFiles(e.clipboardData.files);
  });

  // Viewer
  $('#dlg-view').addEventListener('close', e => {
    if (e.target.open) return;
    viewingId = null;
    $('#view-files').innerHTML = '';
  });
  $('#view-edit').addEventListener('click', () => {
    const id = viewingId;
    $('#dlg-view').close();
    openEditor(id, { fromView: true });
  });
  $('#view-delete').addEventListener('click', deleteViewed);
  $('#view-files').addEventListener('click', e => {
    const b = e.target.closest('[data-fid]');
    if (b) openFile(b.dataset.fid);
  });
  $('#view-details').addEventListener('click', async e => {
    const b = e.target.closest('[data-copy]');
    if (!b) return;
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Copied'); }
    catch { toast('Copying is not allowed here. Select the text instead.'); }
  });

  // Full-screen image
  $('#dlg-image').addEventListener('close', closeImage);
  $('#img-zoom').addEventListener('click', () => $('#img-body').classList.toggle('zoomed'));
  $('#img-el').addEventListener('dblclick', () => $('#img-body').classList.toggle('zoomed'));
  $('#img-prev').addEventListener('click', () => imageView && showImage(imageView.files, imageView.index - 1));
  $('#img-next').addEventListener('click', () => imageView && showImage(imageView.files, imageView.index + 1));
  $('#dlg-image').addEventListener('keydown', e => {
    if (!imageView) return;
    if (e.key === 'ArrowLeft') showImage(imageView.files, imageView.index - 1);
    if (e.key === 'ArrowRight') showImage(imageView.files, imageView.index + 1);
  });
  $('#img-save').addEventListener('click', () => {
    if (imageView) saveOrShare(imageView.blob, imageView.files[imageView.index].name);
  });

  // Settings
  $('#set-autolock').addEventListener('change', e => { settings.autolock = +e.target.value; saveSettings().catch(fail); });
  $('#set-lockhide').addEventListener('change', e => { settings.lockOnHide = e.target.checked; saveSettings().catch(fail); });
  $('#set-compress').addEventListener('change', e => { settings.compress = e.target.checked; saveSettings().catch(fail); });
  $('#btn-chpw').addEventListener('click', changePassword);
  $('#btn-export').addEventListener('click', exportBackup);
  $('#btn-import').addEventListener('click', () => pickBackup('merge'));
  $('#btn-wipe').addEventListener('click', wipeVault);
  $('#in-backup').addEventListener('cancel', () => { pickingSince = 0; });
  $('#in-backup').addEventListener('change', e => {
    pickingSince = 0;
    lastActive = Date.now();
    const f = e.target.files[0];
    if (f) importBackup(f);
  });

  // Busy overlay can't be dismissed with Esc.
  $('#busy').addEventListener('cancel', e => e.preventDefault());

  // Auto-lock
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart', 'scroll']) {
    addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true, capture: true });
  }
  setInterval(checkIdle, 10000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      if (settings.lockOnHide && Date.now() - pickingSince > 10 * 60000) lock();
    } else checkIdle();
  });
}

// ---------------------------------------------------------------- start
async function init() {
  if (!window.crypto || !crypto.subtle || !window.indexedDB) {
    document.body.innerHTML = '<p class="no-match">This browser can\'t run Doc Vault securely. Please open it in an up-to-date Chrome or Edge.</p>';
    return;
  }
  wire();
  const slow = setTimeout(() => toast('Storage is busy. Close other Doc Vault windows or tabs, then open it again.', 15000), 6000);
  try {
    db = await openDB();
    clearTimeout(slow);
  } catch (err) {
    clearTimeout(slow);
    document.body.innerHTML = `<p class="no-match">Could not open storage: ${esc(err.message)}</p>`;
    return;
  }
  showScreen(await idb.get('meta', 'vault') ? 'lock' : 'setup');
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || local)) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
}

init();
})();
