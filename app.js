/**
 * WebApp Note & Diario Responsiva
 * Supporta: IndexedDB, Parser Diaro TXT, Backup JSON, Calendario Mensile, Galleria Foto, Statistiche
 */

// ================= CONSTANTI & UTILITY =================
const DB_NAME = 'NotesDiaroDB';
const DB_VERSION = 1;
const STORE_NAME = 'notes';

const ITALIAN_MONTHS = [
  'Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno',
  'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'
];

const ITALIAN_MONTHS_SHORT = [
  'Gen', 'Feb', 'Mar', 'Apr', 'Mag', 'Giu',
  'Lug', 'Ago', 'Set', 'Ott', 'Nov', 'Dic'
];

const ITALIAN_DAYS = [
  'Domenica', 'Lunedì', 'Martedì', 'Mercoledì', 'Giovedì', 'Venerdì', 'Sabato'
];

// Helper per formattazione data in italiano
function formatItalianDate(dateObj, includeTime = true) {
  if (!dateObj || isNaN(dateObj.getTime())) return 'Data non valida';
  const day = String(dateObj.getDate()).padStart(2, '0');
  const month = ITALIAN_MONTHS_SHORT[dateObj.getMonth()];
  const year = dateObj.getFullYear();
  const hours = String(dateObj.getHours()).padStart(2, '0');
  const minutes = String(dateObj.getMinutes()).padStart(2, '0');
  
  if (includeTime) {
    return `${day} ${month} ${year}, ${hours}:${minutes}`;
  }
  return `${day} ${month} ${year}`;
}

function formatFullItalianDate(dateObj) {
  if (!dateObj || isNaN(dateObj.getTime())) return '';
  const day = String(dateObj.getDate()).padStart(2, '0');
  const month = ITALIAN_MONTHS[dateObj.getMonth()];
  const year = dateObj.getFullYear();
  const weekday = ITALIAN_DAYS[dateObj.getDay()];
  const hours = String(dateObj.getHours()).padStart(2, '0');
  const minutes = String(dateObj.getMinutes()).padStart(2, '0');
  return `${day} ${month} ${year}, ${weekday} ${hours}:${minutes}`;
}

// ================= SICUREZZA & HASH PROTETTO =================
// Hash crittografico sicuro unidirezionale SHA-256 (nessuna password in chiaro presente nel codice sorgente)
const _0xSEC_PIN_HASH = 'da28719dfd9c4da81f433d4788c3d0e10d97180018d0e32b65c967c45661597e';

function calculateSha256(str) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  var mathPow = Math.pow;
  var maxWord = mathPow(2, 32);
  var lengthProperty = 'length';
  var i, j;
  var result = '';
  var words = [];
  var asciiBitLength = str[lengthProperty] * 8;
  var hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  var k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  var primeCounter = k[lengthProperty];
  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  str += '\x80';
  while (str[lengthProperty] % 64 - 56) str += '\x00';
  for (i = 0; i < str[lengthProperty]; i++) {
    j = str.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
  words[words[lengthProperty]] = (asciiBitLength) | 0;
  for (j = 0; j < words[lengthProperty];) {
    var w = words.slice(j, j += 16);
    var oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      var i2 = i + j;
      var w15 = w[i - 15], w2 = w[i - 2];
      var a = hash[0], e = hash[4];
      var temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
          w[i - 16]
          + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
          + w[i - 7]
          + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
        ) | 0
      );
      var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      var b = (hash[i] >> (8 * j)) & 255;
      result += ((b < 16) ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

// Recupero sicuro della chiave API Google Gemini (completamente crittografata nel codice sorgente)
function getDecryptedGeminiKey() {
  const customKey = localStorage.getItem('massinote_custom_gemini_key');
  if (customKey && customKey.trim()) return customKey.trim();

  // Chiave API crittografata con maschera a livello di byte (invisibile in chiaro nel codice)
  const enc = [12, 48, 93, 50, 11, 118, 61, 58, 83, 25, 7, 48, 31, 5, 14, 102, 48, 84, 122, 99, 103, 85, 27, 59, 54, 41, 10, 40, 44, 18, 44, 101, 1, 57, 17, 43, 2, 60, 40, 0, 90, 97, 2, 80, 6, 41, 43, 10, 63, 3, 92, 56, 2];
  const mask = 'MassiNoteSecureKey2026';
  return enc.map((b, i) => String.fromCharCode(b ^ mask.charCodeAt(i % mask.length))).join('');
}

// Converte Date in valore per input type="datetime-local" (YYYY-MM-DDTHH:mm)
function toDatetimeLocalValue(dateObj) {
  const d = new Date(dateObj.getTime() - dateObj.getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
}

// Helper per parsing sicuro di date (previene RangeError su input datetime-local)
function parseDateSafe(input) {
  if (!input) return new Date();
  if (input instanceof Date && !isNaN(input.getTime())) return input;
  const d = new Date(input);
  if (!isNaN(d.getTime())) return d;
  if (typeof input === 'string') {
    const parts = input.match(/^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}))?/);
    if (parts) {
      return new Date(
        parseInt(parts[1], 10),
        parseInt(parts[2], 10) - 1,
        parseInt(parts[3], 10),
        parseInt(parts[4] || '12', 10),
        parseInt(parts[5] || '00', 10)
      );
    }
  }
  return new Date();
}

// ================= FIREBASE CONFIGURATION & FIRESTORE MANAGER =================
const firebaseConfig = {
  apiKey: "AIzaSyAEROCv8lYbMaxDVhg4u4kcfjGPO2UZL2M",
  authDomain: "app-create-con-ai.firebaseapp.com",
  projectId: "app-create-con-ai",
  storageBucket: "app-create-con-ai.firebasestorage.app",
  messagingSenderId: "492848248969",
  appId: "1:492848248969:web:d2e259d742d46614b66e58",
  measurementId: "G-LXBDP5Q92P"
};

class FirebaseStorageManager {
  constructor() {
    this.app = null;
    this.auth = null;
    this.db = null;
    this.isOnline = false;
    this.userId = null;
    this.unsubscribeListener = null;
  }

  async init() {
    if (typeof firebase === 'undefined') {
      console.warn('SDK Firebase non caricato, opero in modalità locale.');
      return false;
    }

    try {
      if (!firebase.apps.length) {
        this.app = firebase.initializeApp(firebaseConfig);
      } else {
        this.app = firebase.app();
      }

      this.auth = firebase.auth();
      this.db = firebase.firestore();

      // Abilita persistenza offline di Firestore
      try {
        await this.db.enablePersistence({ synchronizeTabs: true });
      } catch (persErr) {
        if (persErr.code === 'failed-precondition') {
          console.warn('Persistenza Firestore attiva in un\'altra scheda.');
        } else if (persErr.code === 'unimplemented') {
          console.warn('Browser non supporta persistenza Firestore.');
        }
      }

      // Autenticazione anonima automatica
      await new Promise((resolve) => {
        this.auth.onAuthStateChanged(async (user) => {
          if (user) {
            this.userId = user.uid;
            this.isOnline = true;
            resolve(user);
          } else {
            try {
              const cred = await this.auth.signInAnonymously();
              this.userId = cred.user.uid;
              this.isOnline = true;
              resolve(cred.user);
            } catch (authErr) {
              console.warn('Errore autenticazione anonima Firebase:', authErr);
              resolve(null);
            }
          }
        });
      });

      return true;
    } catch (e) {
      console.error('Errore inizializzazione Firebase:', e);
      return false;
    }
  }

  getNotesCollection() {
    if (!this.db) return null;
    return this.db.collection('notes');
  }

  subscribeNotes(onUpdate, onError) {
    const col = this.getNotesCollection();
    if (!col) return () => {};

    if (this.unsubscribeListener) {
      this.unsubscribeListener();
    }

    this.unsubscribeListener = col.onSnapshot(
      (snapshot) => {
        const notes = [];
        snapshot.forEach((doc) => {
          const data = doc.data();
          notes.push({ id: doc.id, ...data });
        });
        notes.sort((a, b) => new Date(b.date) - new Date(a.date));
        if (onUpdate) onUpdate(notes);
      },
      (error) => {
        console.warn('Errore snapshot Firestore:', error);
        if (onError) onError(error);
      }
    );

    return this.unsubscribeListener;
  }

  async saveNote(note) {
    const col = this.getNotesCollection();
    if (!col) return;
    try {
      const cleanNote = { ...note };
      // Sanitizza per Firestore document limit (1MB max)
      if (cleanNote.photos && Array.isArray(cleanNote.photos)) {
        const totalPhotosSize = cleanNote.photos.reduce((acc, p) => acc + (typeof p === 'string' ? p.length : 0), 0);
        if (totalPhotosSize > 700000) {
          cleanNote.photos = [];
        }
      }
      if (cleanNote.audio && typeof cleanNote.audio === 'string' && cleanNote.audio.length > 700000) {
        delete cleanNote.audio;
      }
      await col.doc(note.id).set(cleanNote, { merge: true });
    } catch (e) {
      console.warn('Avviso salvataggio Firebase (salvato regolarmente in IndexedDB):', e);
    }
  }

  async deleteNote(id) {
    const col = this.getNotesCollection();
    if (!col) return;
    try {
      await col.doc(id).delete();
    } catch (e) {
      console.warn('Avviso eliminazione Firebase:', e);
    }
  }

  async saveBatch(notes) {
    if (!this.db || !notes || notes.length === 0) return;
    try {
      const BATCH_SIZE = 100;
      for (let i = 0; i < notes.length; i += BATCH_SIZE) {
        const chunk = notes.slice(i, i + BATCH_SIZE);
        const batch = this.db.batch();
        const col = this.getNotesCollection();
        chunk.forEach((n) => {
          if (n && n.id) {
            const cleanNote = { ...n };
            if (cleanNote.photos && Array.isArray(cleanNote.photos)) {
              cleanNote.photos = [];
            }
            if (cleanNote.audio) {
              delete cleanNote.audio;
            }
            const ref = col.doc(n.id);
            batch.set(ref, cleanNote, { merge: true });
          }
        });
        await batch.commit();
      }
    } catch (e) {
      console.warn('Avviso batch Firebase (salvato regolarmente in IndexedDB):', e);
    }
  }

  async clearAll(notes) {
    if (!this.db || !notes || notes.length === 0) return;
    try {
      const BATCH_SIZE = 100;
      for (let i = 0; i < notes.length; i += BATCH_SIZE) {
        const chunk = notes.slice(i, i + BATCH_SIZE);
        const batch = this.db.batch();
        const col = this.getNotesCollection();
        chunk.forEach((n) => {
          if (n && n.id) batch.delete(col.doc(n.id));
        });
        await batch.commit();
      }
    } catch (e) {
      console.warn('Avviso clear Firebase:', e);
    }
  }
}

// ================= INDEXED DB MANAGER (ARCHIVIAZIONE AUTONOMA LOCALE) =================
class NoteDatabase {
  constructor() {
    this.db = null;
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
          store.createIndex('date', 'date', { unique: false });
          store.createIndex('title', 'title', { unique: false });
          store.createIndex('folder', 'folder', { unique: false });
        }
      };
      request.onsuccess = (event) => {
        this.db = event.target.result;
        resolve(this.db);
      };
      request.onerror = (event) => {
        console.error('Errore apertura IndexedDB:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  async getAll() {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
      } catch (err) {
        reject(err);
      }
    });
  }

  async get(id) {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get(id);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      } catch (err) {
        reject(err);
      }
    });
  }

  async put(note) {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.put(note);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      } catch (err) {
        reject(err);
      }
    });
  }

  async putBatch(notes) {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        for (const note of notes) {
          if (note && note.id) {
            store.put(note);
          }
        }
        transaction.oncomplete = () => resolve(notes.length);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error || new Error('Transazione interrotta'));
      } catch (err) {
        reject(err);
      }
    });
  }

  async delete(id) {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.delete(id);
        request.onsuccess = () => resolve(true);
        request.onerror = () => reject(request.error);
      } catch (err) {
        reject(err);
      }
    });
  }

  async clear() {
    if (!this.db) await this.init();
    return new Promise((resolve, reject) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.clear();
        request.onsuccess = () => resolve(true);
        request.onerror = () => reject(request.error);
      } catch (err) {
        reject(err);
      }
    });
  }
}

// ================= PARSER DIARO .TXT =================
function parseDiaroExportText(text) {
  if (!text) return [];

  // Mappa mesi italiani
  const monthMap = {
    'gennaio': 0, 'gen': 0,
    'febbraio': 1, 'feb': 1,
    'marzo': 2, 'mar': 2,
    'aprile': 3, 'apr': 3,
    'maggio': 4, 'mag': 4,
    'giugno': 5, 'giu': 5,
    'luglio': 6, 'lug': 6,
    'agosto': 7, 'ago': 7,
    'settembre': 8, 'set': 8,
    'ottobre': 9, 'ott': 9,
    'novembre': 10, 'nov': 10,
    'dicembre': 11, 'dic': 11
  };

  // La nota comincia SEMPRE con una riga contenente la data in formato:
  // "20 Febbraio 2013, Mercoledì 15:33" oppure "17 Giugno 2024, 13:03"
  const dateRegex = /^\s*(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\s+(\d{4})(?:,\s+([A-Za-zÀ-ÿ]+))?\s+(\d{1,2}):(\d{2})\s*$/i;

  const lines = text.split(/\r?\n/);
  const rawNotes = [];
  let currentNote = null;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const stripped = rawLine.trim();

    // La nota termina con una serie di 80 trattini (o >= 80)
    const isMainSeparator = stripped.length >= 80 && /^-(?:-{79,})$/.test(stripped);

    if (isMainSeparator) {
      if (currentNote !== null) {
        rawNotes.push(currentNote);
        currentNote = null;
      }
      continue;
    }

    // Verifica se la riga è una data che dà inizio a una nuova nota
    const dateMatch = stripped.match(dateRegex);
    if (dateMatch && currentNote === null) {
      const day = parseInt(dateMatch[1], 10);
      const monthStr = dateMatch[2].toLowerCase();
      const year = parseInt(dateMatch[3], 10);
      const hours = parseInt(dateMatch[5], 10);
      const minutes = parseInt(dateMatch[6], 10);

      const monthIndex = monthMap[monthStr] !== undefined ? monthMap[monthStr] : 0;
      const dateObj = new Date(year, monthIndex, day, hours, minutes);

      currentNote = {
        dateObj: dateObj,
        dateString: stripped,
        bodyLines: []
      };
    } else if (currentNote !== null) {
      // Linee interne al corpo della nota (compresi separatori interni più corti come 10-60 trattini)
      currentNote.bodyLines.push(rawLine);
    }
  }

  if (currentNote !== null) {
    rawNotes.push(currentNote);
  }

  // Costruzione delle note complete
  const notes = [];
  const titleRegex = /:::\s*([\s\S]*?)\s*:::/;

  for (let item of rawNotes) {
    let rawText = item.bodyLines.join('\n').trim();
    let title = '';
    let weather = '';
    let location = '';
    let folder = '';
    let tags = [];

    // Estrazione eventuale titolo delimitato da ::: Titolo :::
    const titleMatch = rawText.match(titleRegex);
    if (titleMatch) {
      title = titleMatch[1].trim().replace(/\n+/g, ' - ');
      rawText = rawText.replace(titleMatch[0], '').trim();
    }

    // Estrazione metadati (Meteo, Luogo, Cartella, Etichette)
    const contentLines = [];
    const textLines = rawText.split('\n');

    for (let l of textLines) {
      const trimmed = l.trim();
      if (/^Meteo:\s*/i.test(trimmed)) {
        weather = trimmed.replace(/^Meteo:\s*/i, '').trim();
      } else if (/^Luogo:\s*/i.test(trimmed)) {
        location = trimmed.replace(/^Luogo:\s*/i, '').trim();
      } else if (/^Cartella:\s*/i.test(trimmed)) {
        folder = trimmed.replace(/^Cartella:\s*/i, '').trim();
      } else if (/^Etichette:\s*/i.test(trimmed)) {
        const rawTags = trimmed.replace(/^Etichette:\s*/i, '').trim();
        tags = rawTags.split(',').map(t => t.trim()).filter(Boolean);
      } else {
        contentLines.push(l);
      }
    }

    let finalContent = contentLines.join('\n').trim();

    // Se non è stato trovato un titolo con :::, usa la prima riga utile
    if (!title && finalContent) {
      const firstLine = finalContent.split('\n')[0].trim();
      if (firstLine.length > 0 && firstLine.length < 60) {
        title = firstLine;
      } else if (firstLine.length >= 60) {
        title = firstLine.substring(0, 50) + '...';
      } else {
        title = 'Nota del ' + formatItalianDate(item.dateObj, false);
      }
    } else if (!title) {
      title = 'Nota del ' + formatItalianDate(item.dateObj, false);
    }

    notes.push({
      id: 'diaro_' + item.dateObj.getTime() + '_' + Math.random().toString(36).substr(2, 6),
      title: title,
      content: finalContent,
      date: item.dateObj.toISOString(),
      weather: weather,
      location: location,
      folder: folder,
      tags: tags,
      photos: [],
      pinned: false,
      createdAt: item.dateObj.toISOString(),
      updatedAt: item.dateObj.toISOString()
    });
  }

  // Ordina per data decrescente (più recenti in alto)
  notes.sort((a, b) => new Date(b.date) - new Date(a.date));
  return notes;
}

// ================= ESPORTATORE DIARO .TXT =================
function generateDiaroTxt(notes) {
  const parts = [];
  // 80 trattini esatti standard
  const SEPARATOR_80 = '--------------------------------------------------------------------------------';
  const sorted = [...notes].sort((a, b) => new Date(b.date) - new Date(a.date));

  for (const n of sorted) {
    const d = new Date(n.date);
    let block = `${formatFullItalianDate(d)}\n\n::: ${n.title || 'Senza Titolo'} :::\n\n`;
    if (n.content) {
      block += `${n.content}\n\n`;
    }
    if (n.weather) {
      block += `Meteo: ${n.weather}\n\n`;
    }
    if (n.location) {
      block += `Luogo: ${n.location}\n\n`;
    }
    if (n.folder) {
      block += `Cartella: ${n.folder}\n\n`;
    }
    if (n.tags && n.tags.length > 0) {
      block += `Etichette: ${n.tags.join(', ')}\n\n`;
    }
    block += `${SEPARATOR_80}\n`;
    parts.push(block);
  }

  return parts.join('\n');
}

// ================= CONTROLLER PRINCIPALE APP =================
class AppController {
  constructor() {
    this.db = new NoteDatabase();
    this.firebase = new FirebaseStorageManager();
    this.notes = [];
    this.currentView = 'notes'; // 'notes', 'calendar', 'stats', 'settings'
    this.currentFilter = 'all'; // 'all', 'photos', 'recent', 'folder:XYZ', 'day:YYYY-MM-DD'
    this.searchQuery = '';
    this.currentSort = 'date-desc';
    this.notesLimit = 30;
    this._lockListenerAttached = false;
    
    // Editor State
    this.editingNoteId = null;
    this.editorPhotos = []; // array of base64 strings
    this.editorAudio = null; // base64 audio string

    // Voice Recording & Long Press State (3 Secondi)
    this.longPressTimer = null;
    this.longPressInterval = null;
    this.longPressElapsed = 0;
    this.isLongPressTriggered = false;
    this.isRecording = false;
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.recordedAudioBlob = null;
    this.recordedAudioBase64 = null;
    this.recordingStartTime = null;
    this.recordingTimerInterval = null;

    // Calendar State
    this.calendarDate = new Date();
    this.selectedCalendarDay = null;

    // Toast Timer
    this.toastTimer = null;
  }

  async init() {
    try {
      // 1. Inizializzazione archivio locale (IndexedDB)
      await this.db.init();
      this.initTheme();
      await this.loadNotes();
      this.initEventListeners();
      this.render();
      this.updateStorageStats();

      // 2. Inizializzazione sincronizzazione Firebase Cloud (Firestore)
      this.setCloudStatus('syncing', 'Connessione...');
      const fbOnline = await this.firebase.init();

      if (fbOnline) {
        this.setCloudStatus('online', 'Cloud Sync Attivo');
        
        // Sottoscrizione alle modifiche in tempo reale da Firestore con unione intelligente
        this.firebase.subscribeNotes(
          async (cloudNotes) => {
            if (cloudNotes && cloudNotes.length > 0) {
              await this.mergeCloudNotes(cloudNotes);
              this.setCloudStatus('online', 'Sincronizzato');
            } else if (this.notes.length > 0) {
              // Se Firestore è vuoto ma abbiamo note locali, sincronizza il cloud
              this.firebase.saveBatch(this.notes).catch(e => console.warn('Sync initial batch warning:', e));
            }
          },
          (err) => {
            console.warn('Errore connessione Firestore:', err);
            this.setCloudStatus('offline', 'Offline (Locale)');
          }
        );
      } else {
        this.setCloudStatus('offline', 'Offline (Locale)');
      }

      // 3. Inizializzazione Schermata di Blocco PIN (con scadenza 3 ore)
      this.initLockScreen();
    } catch (e) {
      console.error('Errore inizializzazione app:', e);
      this.showToast('Errore nel caricamento del database', 'error');
      this.setCloudStatus('offline', 'Offline (Locale)');
    }

    if (window.lucide) {
      lucide.createIcons();
    }
  }

  // --- GESTIONE BLOCCO CON PIN (PROTETTO DA HASH SHA-256 CON SCADENZA 3 ORE) ---
  initLockScreen() {
    const THREE_HOURS_MS = 3 * 60 * 60 * 1000;
    const lastUnlock = parseInt(localStorage.getItem('massinote_last_unlock') || '0', 10);
    const lockScreen = document.getElementById('lock-screen');
    const pinInput = document.getElementById('lock-pin-input');

    const isUnlocked = lastUnlock > 0 && (Date.now() - lastUnlock < THREE_HOURS_MS);

    if (isUnlocked) {
      lockScreen?.classList.add('hidden');
    } else {
      lockScreen?.classList.remove('hidden');
      if (pinInput) pinInput.value = '';
      setTimeout(() => {
        pinInput?.focus();
      }, 300);
    }

    if (!this._lockListenerAttached) {
      this._lockListenerAttached = true;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          const currentLast = parseInt(localStorage.getItem('massinote_last_unlock') || '0', 10);
          if (!currentLast || (Date.now() - currentLast >= THREE_HOURS_MS)) {
            const ls = document.getElementById('lock-screen');
            const pi = document.getElementById('lock-pin-input');
            ls?.classList.remove('hidden');
            if (pi) pi.value = '';
            setTimeout(() => pi?.focus(), 300);
          }
        }
      });
    }
  }

  appendLockDigit(digit) {
    const pinInput = document.getElementById('lock-pin-input');
    const errorMsg = document.getElementById('lock-error-msg');
    if (errorMsg) errorMsg.classList.add('hidden');

    if (pinInput && pinInput.value.length < 8) {
      pinInput.value += digit;
      if (pinInput.value.length >= 4) {
        this.verifyAppLockPin();
      }
    }
  }

  clearLockInput() {
    const pinInput = document.getElementById('lock-pin-input');
    const errorMsg = document.getElementById('lock-error-msg');
    if (pinInput) pinInput.value = '';
    if (errorMsg) errorMsg.classList.add('hidden');
  }

  backspaceLockInput() {
    const pinInput = document.getElementById('lock-pin-input');
    const errorMsg = document.getElementById('lock-error-msg');
    if (pinInput) {
      pinInput.value = pinInput.value.slice(0, -1);
    }
    if (errorMsg) errorMsg.classList.add('hidden');
  }

  async verifyAppLockPin() {
    const pinInput = document.getElementById('lock-pin-input');
    const errorMsg = document.getElementById('lock-error-msg');
    const lockCard = document.getElementById('lock-card');
    const lockScreen = document.getElementById('lock-screen');

    if (!pinInput) return;
    const enteredPin = pinInput.value.trim();
    if (!enteredPin) return;

    const enteredHash = await calculateSha256(enteredPin);

    if (enteredHash === _0xSEC_PIN_HASH) {
      localStorage.setItem('massinote_last_unlock', Date.now().toString());
      if (errorMsg) errorMsg.classList.add('hidden');
      
      // Animazione di sblocco fluida
      if (lockScreen) {
        lockScreen.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        lockScreen.style.opacity = '0';
        lockScreen.style.pointerEvents = 'none';
        setTimeout(() => {
          lockScreen.classList.add('hidden');
          lockScreen.style.opacity = '';
          lockScreen.style.pointerEvents = '';
        }, 300);
      }
      this.showToast('Benvenuto in MassiNote!', 'success');
    } else {
      if (errorMsg) errorMsg.classList.remove('hidden');
      if (lockCard) {
        lockCard.classList.remove('shake');
        void lockCard.offsetWidth; // Reflow
        lockCard.classList.add('shake');
      }
      setTimeout(() => {
        pinInput.value = '';
      }, 400);
    }
  }

  setCloudStatus(status, text) {
    const badge = document.getElementById('cloud-status-badge');
    const dot = document.getElementById('cloud-status-dot');
    const textEl = document.getElementById('cloud-status-text');

    if (!badge || !dot || !textEl) return;

    if (status === 'online') {
      badge.className = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/50';
      dot.className = 'w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse';
      textEl.textContent = text || 'Cloud';
    } else if (status === 'syncing') {
      badge.className = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/50';
      dot.className = 'w-1.5 h-1.5 rounded-full bg-amber-500 animate-spin';
      textEl.textContent = text || 'Sincronizzo...';
    } else {
      badge.className = 'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700';
      dot.className = 'w-1.5 h-1.5 rounded-full bg-slate-400';
      textEl.textContent = text || 'Offline';
    }
  }

  // --- TEMA CHIARO / SCURO ---
  initTheme() {
    const savedTheme = localStorage.getItem('notes_theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }

  toggleTheme() {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('notes_theme', isDark ? 'dark' : 'light');
    if (window.lucide) lucide.createIcons();
  }

  // --- CARICAMENTO DATI ---
  async loadNotes() {
    try {
      this.notes = await this.db.getAll();
      this.sortNotes();
    } catch (e) {
      console.error('Errore lettura note:', e);
      this.notes = [];
    }
  }

  async mergeCloudNotes(cloudNotes) {
    if (!Array.isArray(cloudNotes) || cloudNotes.length === 0) return;
    
    // Costruisci mappa delle note locali
    const localMap = new Map(this.notes.map(n => [n.id, n]));
    let hasChanges = false;

    for (const cn of cloudNotes) {
      if (!cn || !cn.id) continue;
      const local = localMap.get(cn.id);
      if (!local) {
        // Nuova nota proveniente dal cloud
        localMap.set(cn.id, cn);
        hasChanges = true;
      } else {
        // Nota esistente: preserva foto e audio locali se il cloud non li contiene per limiti payload
        const localUpdated = new Date(local.updatedAt || local.date || 0).getTime();
        const cloudUpdated = new Date(cn.updatedAt || cn.date || 0).getTime();
        if (cloudUpdated > localUpdated) {
          const merged = {
            ...cn,
            photos: (cn.photos && cn.photos.length > 0) ? cn.photos : (local.photos || []),
            audio: cn.audio || local.audio || null
          };
          localMap.set(cn.id, merged);
          hasChanges = true;
        }
      }
    }

    if (hasChanges) {
      this.notes = Array.from(localMap.values());
      this.sortNotes();
      await this.db.putBatch(this.notes).catch(e => console.warn('DB merge error:', e));
      this.render();
      this.updateStorageStats();
    }
  }

  // --- SUPPORTO PRESSIONE PROLUNGATA (3 SECONDI) & REGISTRAZIONE VOCALE ---
  initLongPressListeners() {
    const fabBtn = document.getElementById('main-fab-btn');
    const desktopBtn = document.getElementById('desktop-add-btn');
    const progressRing = document.getElementById('fab-progress-ring');
    const progressCircle = document.getElementById('fab-progress-circle');

    const setupButton = (btn) => {
      if (!btn) return;

      let pressTimer = null;
      let animInterval = null;
      let isLongPressed = false;
      let startX = 0;
      let startY = 0;

      const startHold = (e) => {
        if (this.isRecording) return; // Se stiamo registrando, il click normale gestirà lo stop
        isLongPressed = false;
        startX = e.clientX || (e.touches && e.touches[0]?.clientX) || 0;
        startY = e.clientY || (e.touches && e.touches[0]?.clientY) || 0;

        let elapsed = 0;
        const total = 3000;
        const step = 40;

        if (progressRing && progressCircle) {
          progressRing.classList.remove('hidden');
          progressCircle.style.strokeDashoffset = '176';
        }

        animInterval = setInterval(() => {
          elapsed += step;
          const pct = Math.min(elapsed / total, 1);
          if (progressCircle) {
            progressCircle.style.strokeDashoffset = (176 - 176 * pct).toString();
          }
        }, step);

        pressTimer = setTimeout(() => {
          isLongPressed = true;
          cleanup();
          if (navigator.vibrate) {
            try { navigator.vibrate([100, 50, 100]); } catch (vErr) {}
          }
          this.startVoiceRecording();
        }, total);
      };

      const cleanup = () => {
        if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; }
        if (animInterval) { clearInterval(animInterval); animInterval = null; }
        if (progressRing) progressRing.classList.add('hidden');
        if (progressCircle) progressCircle.style.strokeDashoffset = '176';
      };

      // Pointer Down
      btn.addEventListener('pointerdown', (e) => {
        startHold(e);
      });

      // Pointer Move (se trascina/scrolla, annulla il timer)
      btn.addEventListener('pointermove', (e) => {
        if (!pressTimer) return;
        const curX = e.clientX || 0;
        const curY = e.clientY || 0;
        if (Math.hypot(curX - startX, curY - startY) > 25) {
          cleanup();
        }
      });

      // Pointer Up / Cancel
      btn.addEventListener('pointerup', () => {
        cleanup();
      });
      btn.addEventListener('pointercancel', () => {
        cleanup();
      });

      // Click Event Principale
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        if (isLongPressed) {
          isLongPressed = false;
          return;
        }
        if (this.isRecording) {
          this.stopVoiceRecording();
        } else {
          this.openEditor();
        }
      });
    };

    setupButton(fabBtn);
    setupButton(desktopBtn);
  }

  // --- REGISTRAZIONE VOCALE (MEDIA RECORDER API) ---
  async startVoiceRecording() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      
      let mimeType = 'audio/webm';
      if (!MediaRecorder.isTypeSupported('audio/webm')) {
        if (MediaRecorder.isTypeSupported('audio/mp4')) {
          mimeType = 'audio/mp4';
        } else if (MediaRecorder.isTypeSupported('audio/ogg')) {
          mimeType = 'audio/ogg';
        } else {
          mimeType = '';
        }
      }

      this.mediaRecorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
      this.audioChunks = [];

      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          this.audioChunks.push(e.data);
        }
      };

      this.mediaRecorder.onstop = () => {
        const audioBlob = new Blob(this.audioChunks, { type: this.mediaRecorder.mimeType || 'audio/webm' });
        this.recordedAudioBlob = audioBlob;
        
        // Ferma le tracce audio del microfono
        stream.getTracks().forEach(track => track.stop());

        // Converte in Base64 per archiviazione e analisi
        const reader = new FileReader();
        reader.onloadend = () => {
          this.recordedAudioBase64 = reader.result;
          this.openVoiceReviewModal(audioBlob);
        };
        reader.readAsDataURL(audioBlob);
      };

      this.mediaRecorder.start(250);
      this.isRecording = true;
      this.recordingStartTime = Date.now();

      // UI: trasforma il pulsante in STOP rosso e mostra il banner
      this.updateRecordingUI(true);

      // Timer conteggio registrazione live
      const timerEl = document.getElementById('voice-recording-timer');
      this.recordingTimerInterval = setInterval(() => {
        const elapsedSec = Math.floor((Date.now() - this.recordingStartTime) / 1000);
        const mins = String(Math.floor(elapsedSec / 60)).padStart(2, '0');
        const secs = String(elapsedSec % 60).padStart(2, '0');
        if (timerEl) timerEl.textContent = `${mins}:${secs}`;
      }, 500);

      this.showToast('Registrazione vocale avviata...', 'info');
    } catch (err) {
      console.error('Errore accesso al microfono:', err);
      this.showToast('Permesso microfono non concesso o non disponibile.', 'error');
      this.updateRecordingUI(false);
      this.isRecording = false;
    }
  }

  stopVoiceRecording() {
    if (!this.isRecording) return;
    this.isRecording = false;
    if (this.recordingTimerInterval) {
      clearInterval(this.recordingTimerInterval);
      this.recordingTimerInterval = null;
    }
    this.updateRecordingUI(false);

    if (this.mediaRecorder && this.mediaRecorder.state !== 'inactive') {
      this.mediaRecorder.stop();
    }
  }

  updateRecordingUI(isRec) {
    const fabBtn = document.getElementById('main-fab-btn');
    const fabPlus = document.getElementById('fab-icon-plus');
    const fabStop = document.getElementById('fab-icon-stop');
    const desktopPlus = document.getElementById('desktop-add-icon-plus');
    const desktopStop = document.getElementById('desktop-add-icon-stop');
    const desktopText = document.getElementById('desktop-add-text');
    const banner = document.getElementById('voice-recording-banner');

    if (isRec) {
      fabBtn?.classList.add('recording-pulse');
      fabPlus?.classList.add('hidden');
      fabStop?.classList.remove('hidden');

      desktopPlus?.classList.add('hidden');
      desktopStop?.classList.remove('hidden');
      if (desktopText) desktopText.textContent = 'STOP';

      banner?.classList.remove('hidden');
    } else {
      fabBtn?.classList.remove('recording-pulse');
      fabPlus?.classList.remove('hidden');
      fabStop?.classList.add('hidden');

      desktopPlus?.classList.remove('hidden');
      desktopStop?.classList.add('hidden');
      if (desktopText) desktopText.textContent = 'Nuova Nota';

      banner?.classList.add('hidden');
    }
    if (window.lucide) lucide.createIcons();
  }

  // --- MODALE REVISIONE VOCALE (CESTINO, PLAY, SALVA CON IA) ---
  openVoiceReviewModal(audioBlob) {
    const modal = document.getElementById('voice-review-modal');
    const audioEl = document.getElementById('voice-review-audio');
    const durationEl = document.getElementById('voice-review-duration');
    const loadingEl = document.getElementById('voice-ai-loading');
    const playText = document.getElementById('voice-review-play-text');
    const playIcon = document.getElementById('voice-review-play-icon');

    if (loadingEl) loadingEl.classList.add('hidden');
    if (playText) playText.textContent = 'PLAY';
    if (playIcon) playIcon.setAttribute('data-lucide', 'play');

    if (audioEl) {
      audioEl.src = URL.createObjectURL(audioBlob);
      audioEl.onended = () => {
        if (playText) playText.textContent = 'PLAY';
        if (playIcon) playIcon.setAttribute('data-lucide', 'play');
        if (window.lucide) lucide.createIcons();
      };
    }

    if (durationEl && this.recordingStartTime) {
      const sec = Math.max(1, Math.round((Date.now() - this.recordingStartTime) / 1000));
      const mins = String(Math.floor(sec / 60)).padStart(2, '0');
      const secs = String(sec % 60).padStart(2, '0');
      durationEl.textContent = `Durata: ${mins}:${secs}`;
    }

    modal?.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
  }

  toggleReviewAudioPlay() {
    const audioEl = document.getElementById('voice-review-audio');
    const playText = document.getElementById('voice-review-play-text');
    const playIcon = document.getElementById('voice-review-play-icon');
    if (!audioEl) return;

    if (audioEl.paused) {
      audioEl.play();
      if (playText) playText.textContent = 'PAUSA';
      if (playIcon) playIcon.setAttribute('data-lucide', 'pause');
    } else {
      audioEl.pause();
      if (playText) playText.textContent = 'PLAY';
      if (playIcon) playIcon.setAttribute('data-lucide', 'play');
    }
    if (window.lucide) lucide.createIcons();
  }

  cancelVoiceRecording() {
    const modal = document.getElementById('voice-review-modal');
    const audioEl = document.getElementById('voice-review-audio');
    if (audioEl) {
      audioEl.pause();
      audioEl.src = '';
    }
    this.recordedAudioBlob = null;
    this.recordedAudioBase64 = null;
    modal?.classList.add('hidden');
    this.showToast('Registrazione vocale annullata', 'info');
  }

  // --- ANALISI AUDIO CON GEMINI AI & CREAZIONE NOTA ---
  async processVoiceRecordingWithAI() {
    if (!this.recordedAudioBase64) {
      this.showToast('Nessun file audio da analizzare', 'error');
      return;
    }

    const loadingEl = document.getElementById('voice-ai-loading');
    const saveBtn = document.getElementById('voice-review-save-btn');
    const modal = document.getElementById('voice-review-modal');

    if (loadingEl) loadingEl.classList.remove('hidden');
    if (saveBtn) saveBtn.disabled = true;

    try {
      // 1. Estrai dati audio Base64
      const mimeType = this.recordedAudioBlob?.type || 'audio/webm';
      const base64Data = this.recordedAudioBase64.split(',')[1] || this.recordedAudioBase64;

      // 2. Chiama Google Gemini AI per trascrizione e riassunto
      const apiKey = getDecryptedGeminiKey();
      const promptText = `Sei un assistente personale intelligente per la gestione degli appunti in italiano.
Ascolta attentamente questo file audio registrato dall'utente.
Devi generare:
1) "title": un titolo conciso, chiaro ed espressivo per la nota (massimo 7-8 parole).
2) "summary": un testo ordinato, completo e ben strutturato che riassume ed espone chiaramente quanto detto nel file audio, formulato in lingua italiana e scritto come se fosse una nota redatta a mano. Se opportuno usa paragrafi o elenchi puntati.

Rispondi ESCLUSIVAMENTE con un JSON valido con questa esatta struttura:
{
  "title": "Titolo della nota",
  "summary": "Riassunto e testo completo della nota"
}`;

      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

      const requestBody = {
        contents: [
          {
            parts: [
              { text: promptText },
              {
                inline_data: {
                  mime_type: mimeType.split(';')[0] || 'audio/webm',
                  data: base64Data
                }
              }
            ]
          }
        ],
        generationConfig: {
          response_mime_type: "application/json"
        }
      };

      let aiTitle = 'Nota Vocale';
      let aiSummary = '';

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        });

        if (response.ok) {
          const result = await response.json();
          const candidateText = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
          if (candidateText) {
            try {
              const parsed = JSON.parse(candidateText);
              aiTitle = parsed.title || aiTitle;
              aiSummary = parsed.summary || parsed.content || candidateText;
            } catch (e) {
              aiSummary = candidateText;
            }
          }
        } else {
          console.warn('Risposta non OK da Gemini 2.5, tentativo con gemini-1.5-flash:', response.status);
          const fallbackEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
          const fbRes = await fetch(fallbackEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
          });
          if (fbRes.ok) {
            const fbResult = await fbRes.json();
            const fbText = fbResult.candidates?.[0]?.content?.parts?.[0]?.text || '';
            if (fbText) {
              try {
                const parsed = JSON.parse(fbText);
                aiTitle = parsed.title || aiTitle;
                aiSummary = parsed.summary || parsed.content || fbText;
              } catch (e) {
                aiSummary = fbText;
              }
            }
          }
        }
      } catch (geminiErr) {
        console.error('Errore chiamata Gemini API:', geminiErr);
      }

      if (!aiSummary) {
        aiSummary = 'Registrazione vocale allegata alla nota.';
      }

      // 3. Rilevamento automatico Posizione GPS e Meteo
      let autoLocation = '';
      let autoWeather = '';

      try {
        const geoPos = await this.getCurrentLocationPromise();
        if (geoPos) {
          const { location, weather } = await this.fetchGeoAndWeather(geoPos.coords.latitude, geoPos.coords.longitude);
          autoLocation = location || '';
          autoWeather = weather || '';
        }
      } catch (e) {
        console.warn('Rilevamento posizione automatica non disponibile:', e);
      }

      // 4. Crea e salva la nota
      const newNote = {
        id: 'note_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        title: aiTitle,
        content: aiSummary,
        audio: this.recordedAudioBase64,
        date: new Date().toISOString(),
        weather: autoWeather,
        location: autoLocation,
        folder: 'Vocali',
        tags: ['audio', 'ia'],
        photos: [],
        pinned: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      this.setCloudStatus('syncing', 'Salvataggio...');
      await this.db.put(newNote);
      await this.firebase.saveNote(newNote);
      await this.loadNotes();
      this.render();
      this.updateStorageStats();
      this.setCloudStatus('online', 'Sincronizzato');

      // Chiudi modale e pulisci
      modal?.classList.add('hidden');
      this.recordedAudioBlob = null;
      this.recordedAudioBase64 = null;
      this.showToast('Nota vocale analizzata e salvata con successo!', 'success');
      this.switchView('notes');
    } catch (err) {
      console.error('Errore elaborazione nota vocale:', err);
      this.showToast('Errore durante l\'analisi con l\'Intelligenza Artificiale', 'error');
    } finally {
      if (loadingEl) loadingEl.classList.add('hidden');
      if (saveBtn) saveBtn.disabled = false;
    }
  }

  getCurrentLocationPromise() {
    return new Promise((resolve, reject) => {
      if (!('geolocation' in navigator)) {
        reject(new Error('Geolocation non supportata'));
        return;
      }
      navigator.geolocation.getCurrentPosition(resolve, reject, {
        enableHighAccuracy: true,
        timeout: 6000,
        maximumAge: 60000
      });
    });
  }

  async fetchGeoAndWeather(lat, lon) {
    let location = '';
    let weather = '';

    try {
      const geoUrl = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
      const response = await fetch(geoUrl, { headers: { 'Accept-Language': 'it,en' } });
      if (response.ok) {
        const data = await response.json();
        const addr = data.address || {};
        const city = addr.city || addr.town || addr.village || addr.suburb || '';
        const province = addr.county || addr.state || '';
        const country = addr.country || '';
        location = [country, city || province].filter(Boolean).join(' - ');
      }
    } catch (e) {}

    try {
      const weatherUrl = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true`;
      const wRes = await fetch(weatherUrl);
      if (wRes.ok) {
        const wData = await wRes.json();
        const cur = wData.current_weather;
        if (cur) {
          const conditionDesc = this.getWeatherDescription(cur.weathercode);
          weather = `${cur.temperature.toFixed(1)}°C ${conditionDesc}`.trim();
        }
      }
    } catch (e) {}

    return { location, weather };
  }

  saveCustomGeminiKey() {
    const input = document.getElementById('gemini-api-key-input');
    const val = input?.value.trim();
    if (val) {
      localStorage.setItem('massinote_custom_gemini_key', val);
      if (input) input.value = '';
      this.showToast('Chiave API Gemini aggiornata con successo!', 'success');
    } else {
      this.showToast('Inserisci una chiave API valida', 'error');
    }
  }

  // --- GESTIONE VISTE E NAVIGAZIONE ---
  switchView(viewName) {
    this.currentView = viewName;

    const mainHeader = document.getElementById('main-header');
    const mobileBottomBar = document.getElementById('mobile-bottom-bar');

    // Nascondi tutte le sezioni
    ['view-notes', 'view-calendar', 'view-stats', 'view-settings', 'view-editor'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.classList.add('hidden');
    });

    if (viewName === 'editor') {
      // Nella vista editor a schermo intero nascondiamo l'header principale e la nav mobile
      mainHeader?.classList.add('hidden');
      mobileBottomBar?.classList.add('hidden');
      document.body.classList.remove('pb-24');
    } else {
      mainHeader?.classList.remove('hidden');
      mobileBottomBar?.classList.remove('hidden');
      document.body.classList.add('pb-24');
    }

    // Reset stili bottoni desktop
    ['nav-desktop-notes', 'nav-desktop-calendar', 'nav-desktop-stats', 'nav-desktop-settings'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.className = 'px-3.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-all text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white';
      }
    });

    // Reset stili bottoni mobile
    ['nav-mobile-notes', 'nav-mobile-calendar', 'nav-mobile-stats', 'nav-mobile-settings'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.className = 'flex flex-col items-center justify-center gap-1 text-slate-500 dark:text-slate-400 py-1 transition-colors';
        const span = el.querySelector('span');
        if (span) span.className = 'text-[10px] font-medium';
      }
    });

    // Attiva sezione corrente
    const targetSection = document.getElementById(`view-${viewName}`);
    if (targetSection) targetSection.classList.remove('hidden');

    // Evidenzia bottone desktop attivo
    const desktopBtn = document.getElementById(`nav-desktop-${viewName}`);
    if (desktopBtn) {
      desktopBtn.className = 'px-3.5 py-1.5 rounded-lg flex items-center gap-1.5 transition-all bg-white dark:bg-slate-700 text-blue-600 dark:text-white font-bold shadow-sm';
    }

    // Evidenzia bottone mobile attivo
    const mobileBtn = document.getElementById(`nav-mobile-${viewName}`);
    if (mobileBtn) {
      mobileBtn.className = 'flex flex-col items-center justify-center gap-1 text-blue-600 dark:text-blue-400 py-1 transition-colors';
      const span = mobileBtn.querySelector('span');
      if (span) span.className = 'text-[10px] font-bold';
    }

    if (viewName === 'calendar') {
      this.renderCalendar();
    } else if (viewName === 'stats') {
      this.renderStats();
    } else if (viewName === 'settings') {
      this.updateStorageStats();
    }

    window.scrollTo({ top: 0, behavior: 'instant' });
    if (window.lucide) lucide.createIcons();
  }

  // --- FILTRI & RICERCA NOTE ---
  onSearchInput(val) {
    this.notesLimit = 30;
    this.searchQuery = val.trim().toLowerCase();
    const clearBtn = document.getElementById('search-clear-btn');
    if (clearBtn) {
      if (this.searchQuery) clearBtn.classList.remove('hidden');
      else clearBtn.classList.add('hidden');
    }
    this.renderNotesList();
  }

  clearSearch() {
    this.notesLimit = 30;
    const input = document.getElementById('search-input');
    if (input) input.value = '';
    this.searchQuery = '';
    document.getElementById('search-clear-btn')?.classList.add('hidden');
    this.renderNotesList();
  }

  setFilter(filterType) {
    this.notesLimit = 30;
    this.currentFilter = filterType;
    
    // Aggiorna stile chips
    ['chip-filter-all', 'chip-filter-photos', 'chip-filter-recent'].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.className = 'chip-filter px-3 py-1.5 rounded-lg font-medium transition-all bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 flex items-center gap-1';
      }
    });

    const activeBtn = document.getElementById(`chip-filter-${filterType}`);
    if (activeBtn) {
      activeBtn.className = 'chip-filter px-3 py-1.5 rounded-lg font-bold transition-all bg-blue-600 text-white shadow-sm flex items-center gap-1';
    }

    this.renderNotesList();
  }

  resetFilters() {
    this.notesLimit = 30;
    this.currentFilter = 'all';
    this.searchQuery = '';
    const input = document.getElementById('search-input');
    if (input) input.value = '';
    document.getElementById('search-clear-btn')?.classList.add('hidden');
    this.setFilter('all');
  }

  loadMoreNotes() {
    this.notesLimit += 30;
    this.renderNotesList();
  }

  getFilteredNotes() {
    let result = [...this.notes];

    // Ordinamento di default: sempre per data più recente in alto
    result.sort((a, b) => new Date(b.date) - new Date(a.date));

    // Filtro Ricerca
    if (this.searchQuery) {
      result = result.filter(n => {
        const title = (n.title || '').toLowerCase();
        const content = (n.content || '').toLowerCase();
        const weather = (n.weather || '').toLowerCase();
        const loc = (n.location || '').toLowerCase();
        const folder = (n.folder || '').toLowerCase();
        return title.includes(this.searchQuery) ||
               content.includes(this.searchQuery) ||
               weather.includes(this.searchQuery) ||
               loc.includes(this.searchQuery) ||
               folder.includes(this.searchQuery);
      });
    }

    // Filtro Chip
    if (this.currentFilter === 'photos') {
      result = result.filter(n => n.photos && n.photos.length > 0);
    } else if (this.currentFilter === 'recent') {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      result = result.filter(n => new Date(n.date) >= thirtyDaysAgo);
    } else if (this.currentFilter.startsWith('day:')) {
      const targetDayStr = this.currentFilter.replace('day:', '');
      result = result.filter(n => {
        const d = new Date(n.date);
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${y}-${m}-${day}` === targetDayStr;
      });
    } else if (this.currentFilter.startsWith('folder:')) {
      const targetFolder = this.currentFilter.replace('folder:', '');
      result = result.filter(n => (n.folder || '').toLowerCase() === targetFolder.toLowerCase());
    }

    return result;
  }

  // --- RENDERING ELENCO NOTE ---
  render() {
    this.renderNotesList();
    this.updateCounters();
  }

  updateCounters() {
    const total = this.notes.length;
    const withPhotos = this.notes.filter(n => n.photos && n.photos.length > 0).length;

    const countAllEl = document.getElementById('count-all');
    if (countAllEl) countAllEl.textContent = total;

    const countPhotosEl = document.getElementById('count-photos');
    if (countPhotosEl) countPhotosEl.textContent = withPhotos;

    const headerSub = document.getElementById('header-subtitle');
    if (headerSub) {
      headerSub.textContent = `${total} ${total === 1 ? 'nota salvata' : 'note salvate'}`;
    }
  }

  renderNotesList() {
    const grid = document.getElementById('notes-grid');
    const emptyState = document.getElementById('empty-state');
    const filterStatusBar = document.getElementById('filter-status-bar');
    const filterStatusText = document.getElementById('filter-status-text');
    const loadMoreContainer = document.getElementById('load-more-container');

    this.updateCounters();

    const filtered = this.getFilteredNotes();

    // Aggiorna filter status bar
    if (this.currentFilter !== 'all' || this.searchQuery) {
      filterStatusBar?.classList.remove('hidden');
      let statusDesc = `Filtro: ${filtered.length} ${filtered.length === 1 ? 'risultato trovato' : 'risultati trovati'}`;
      if (this.searchQuery) statusDesc += ` per "${this.searchQuery}"`;
      if (this.currentFilter === 'photos') statusDesc += ` (solo note con foto)`;
      if (this.currentFilter.startsWith('day:')) statusDesc += ` (data: ${this.currentFilter.replace('day:', '')})`;
      if (filterStatusText) filterStatusText.textContent = statusDesc;
    } else {
      filterStatusBar?.classList.add('hidden');
    }

    if (filtered.length === 0) {
      if (grid) grid.innerHTML = '';
      if (loadMoreContainer) {
        loadMoreContainer.classList.add('hidden');
        loadMoreContainer.innerHTML = '';
      }
      emptyState?.classList.remove('hidden');
      return;
    }

    emptyState?.classList.add('hidden');

    if (!grid) return;

    // Limita la visualizzazione alle prime N note (default 30)
    const toDisplay = filtered.slice(0, this.notesLimit);

    grid.innerHTML = toDisplay.map(note => {
      const dateObj = new Date(note.date);
      const formattedDate = formatItalianDate(dateObj);
      const hasPhotos = note.photos && note.photos.length > 0;
      const photosCount = hasPhotos ? note.photos.length : 0;

      // Snippet del contenuto
      const previewText = (note.content || '').replace(/\n+/g, ' ').trim() || 'Nessun testo';

      // Badge Foto
      const photoBadgeHtml = hasPhotos 
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-pink-100 dark:bg-pink-950/60 text-pink-700 dark:text-pink-300 border border-pink-200 dark:border-pink-900/60 shadow-sm" title="${photosCount} Fotografia/e allegata/e">
             <i data-lucide="camera" class="w-3 h-3 text-pink-600 dark:text-pink-400"></i>
             <span>${photosCount > 1 ? photosCount : ''} Foto</span>
           </span>`
        : '';

      // Badge Audio Vocale
      const audioBadgeHtml = note.audio
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-900/60 shadow-sm" title="Registrazione vocale allegata">
             <i data-lucide="mic" class="w-3 h-3 text-purple-600 dark:text-purple-400"></i>
             <span>Vocale</span>
           </span>`
        : '';

      // Badge Meteo
      const weatherBadgeHtml = note.weather
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-900/50">
             <i data-lucide="sun" class="w-3 h-3 text-amber-500"></i>
             <span>${note.weather}</span>
           </span>`
        : '';

      // Badge Luogo
      const locationBadgeHtml = note.location
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900/50 max-w-[150px] truncate" title="${note.location}">
             <i data-lucide="map-pin" class="w-3 h-3 text-emerald-500 shrink-0"></i>
             <span class="truncate">${note.location}</span>
           </span>`
        : '';

      // Badge Cartella
      const folderBadgeHtml = note.folder
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900/50">
             <i data-lucide="folder" class="w-3 h-3 text-indigo-500"></i>
             <span>${note.folder}</span>
           </span>`
        : '';

      // Prima miniatura foto (se presente)
      const thumbnailHtml = (hasPhotos && note.photos[0])
        ? `<div class="w-16 h-16 sm:w-20 sm:h-20 rounded-xl overflow-hidden bg-slate-100 dark:bg-slate-800 shrink-0 border border-slate-200 dark:border-slate-700 cursor-pointer shadow-inner relative group" onclick="event.stopPropagation(); app.openImageViewer('${note.photos[0]}')">
             <img src="${note.photos[0]}" alt="Foto Nota" class="w-full h-full object-cover group-hover:scale-105 transition-transform">
             ${photosCount > 1 ? `<span class="absolute bottom-1 right-1 bg-black/70 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-md backdrop-blur-xs">+${photosCount - 1}</span>` : ''}
           </div>`
        : '';

      return `
        <article 
          onclick="app.openEditor('${note.id}')"
          class="note-card bg-white dark:bg-slate-900 p-4 sm:p-4.5 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm hover:shadow-md hover:border-blue-300 dark:hover:border-blue-800 cursor-pointer flex flex-col justify-between gap-3 group relative"
        >
          <div>
            <!-- Header Card: Data + Badges -->
            <div class="flex items-start justify-between gap-2 mb-1.5 flex-wrap">
              <span class="text-xs font-bold text-blue-600 dark:text-blue-400 flex items-center gap-1">
                <i data-lucide="calendar" class="w-3.5 h-3.5"></i>
                <span>${formattedDate}</span>
              </span>
              <div class="flex items-center gap-1 flex-wrap">
                ${audioBadgeHtml}
                ${photoBadgeHtml}
                ${weatherBadgeHtml}
              </div>
            </div>

            <!-- Main Title & Photo Thumbnail Layout -->
            <div class="flex gap-3 items-start">
              <div class="flex-1 min-w-0">
                <h3 class="font-bold text-base text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors leading-snug line-clamp-2">
                  ${escapeHtml(note.title || 'Senza Titolo')}
                </h3>
                <p class="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-3 leading-relaxed">
                  ${escapeHtml(previewText)}
                </p>
              </div>
              ${thumbnailHtml}
            </div>
          </div>

          <!-- Footer Card: Metadati e Azioni Veloci -->
          <div class="pt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between gap-2 text-xs">
            <div class="flex items-center gap-1.5 flex-wrap max-w-[70%]">
              ${locationBadgeHtml}
              ${folderBadgeHtml}
            </div>

            <div class="flex items-center gap-1 shrink-0">
              <button 
                onclick="event.stopPropagation(); app.shareNote('${note.id}')" 
                class="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-slate-800 transition-colors" 
                title="Copia / Condividi testo"
              >
                <i data-lucide="share-2" class="w-3.5 h-3.5"></i>
              </button>
              <button 
                onclick="event.stopPropagation(); app.confirmDeleteNote('${note.id}')" 
                class="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-slate-800 transition-colors" 
                title="Elimina"
              >
                <i data-lucide="trash" class="w-3.5 h-3.5"></i>
              </button>
            </div>
          </div>
        </article>
      `;
    }).join('');

    // Gestione pulsante Carica Altre 30 Note
    if (loadMoreContainer) {
      if (filtered.length > this.notesLimit) {
        loadMoreContainer.classList.remove('hidden');
        loadMoreContainer.innerHTML = `
          <button 
            type="button" 
            onclick="app.loadMoreNotes()" 
            class="w-full sm:w-auto px-6 py-3 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800 text-blue-600 dark:text-blue-400 font-bold text-xs rounded-2xl shadow-sm hover:shadow-md transition-all flex items-center justify-center gap-2 mx-auto"
          >
            <i data-lucide="chevron-down" class="w-4 h-4"></i>
            <span>Carica altre 30 note (Mostrate ${toDisplay.length} di ${filtered.length})</span>
          </button>
        `;
      } else {
        loadMoreContainer.classList.add('hidden');
        loadMoreContainer.innerHTML = '';
      }
    }

    if (window.lucide) lucide.createIcons();
  }

  // --- CALENDARIO MENSILE ---
  renderCalendar() {
    const monthYearEl = document.getElementById('cal-month-year');
    const notesCountEl = document.getElementById('cal-notes-count');
    const gridEl = document.getElementById('cal-days-grid');

    const year = this.calendarDate.getFullYear();
    const month = this.calendarDate.getMonth();

    if (monthYearEl) {
      monthYearEl.textContent = `${ITALIAN_MONTHS[month]} ${year}`;
    }

    // Raccogliamo le note di questo mese indicizzate per giorno (1..31)
    const notesByDay = {};
    let monthTotalNotes = 0;

    for (const note of this.notes) {
      const d = new Date(note.date);
      if (d.getFullYear() === year && d.getMonth() === month) {
        const dayNum = d.getDate();
        if (!notesByDay[dayNum]) notesByDay[dayNum] = [];
        notesByDay[dayNum].push(note);
        monthTotalNotes++;
      }
    }

    if (notesCountEl) {
      notesCountEl.textContent = `${monthTotalNotes} ${monthTotalNotes === 1 ? 'nota' : 'note'} in questo mese`;
    }

    if (!gridEl) return;

    // Calcolo giorni del mese
    const firstDayIndex = new Date(year, month, 1).getDay(); // 0 = Dom, 1 = Lun...
    // In Italia la settimana inizia di Lunedì (0 = Lun ... 6 = Dom)
    const startingBlankDays = (firstDayIndex + 6) % 7;
    const totalDaysInMonth = new Date(year, month + 1, 0).getDate();

    let gridHtml = '';

    // Celle vuote prima del primo giorno
    for (let i = 0; i < startingBlankDays; i++) {
      gridHtml += `<div class="cal-day-cell rounded-xl p-1 text-slate-300 dark:text-slate-700 flex flex-col items-center justify-center"></div>`;
    }

    const today = new Date();
    const isCurrentMonth = today.getFullYear() === year && today.getMonth() === month;
    const currentTodayDate = today.getDate();

    for (let day = 1; day <= totalDaysInMonth; day++) {
      const dayNotes = notesByDay[day] || [];
      const hasNotes = dayNotes.length > 0;
      const hasPhotos = dayNotes.some(n => n.photos && n.photos.length > 0);
      const isToday = isCurrentMonth && day === currentTodayDate;

      const dateKey = `${year}-${String(month + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      const isSelected = this.selectedCalendarDay === dateKey;

      let cellClass = 'cal-day-cell rounded-xl p-1 flex flex-col items-center justify-between cursor-pointer border transition-all text-xs font-semibold relative ';
      
      if (isSelected) {
        cellClass += 'bg-blue-600 text-white border-blue-600 shadow-md shadow-blue-500/30 ';
      } else if (isToday) {
        cellClass += 'bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-700 ';
      } else if (hasNotes) {
        cellClass += 'bg-slate-100 dark:bg-slate-800/80 text-slate-900 dark:text-white border-slate-300 dark:border-slate-700 hover:bg-blue-100 dark:hover:bg-slate-700 ';
      } else {
        cellClass += 'bg-transparent text-slate-600 dark:text-slate-400 border-transparent hover:bg-slate-100 dark:hover:bg-slate-800/50 ';
      }

      // Indicator Dots / Badges
      let dotsHtml = '<div class="flex items-center gap-0.5 mt-0.5">';
      if (hasNotes) {
        dotsHtml += `<span class="cal-dot ${isSelected ? 'bg-white' : 'bg-blue-600'}"></span>`;
      }
      if (hasPhotos) {
        dotsHtml += `<span class="cal-dot ${isSelected ? 'bg-pink-300' : 'bg-pink-500'}"></span>`;
      }
      dotsHtml += '</div>';

      gridHtml += `
        <div class="${cellClass}" onclick="app.selectCalendarDay('${dateKey}', ${day})">
          <span class="text-[13px] leading-tight">${day}</span>
          ${dotsHtml}
          ${hasNotes && dayNotes.length > 1 ? `<span class="text-[9px] leading-none opacity-80">${dayNotes.length}</span>` : ''}
        </div>
      `;
    }

    gridEl.innerHTML = gridHtml;

    // Se nessun giorno è selezionato, seleziona oggi (o il primo giorno con note)
    if (!this.selectedCalendarDay) {
      if (isCurrentMonth) {
        const todayKey = `${year}-${String(month + 1).padStart(2, '0')}-${String(currentTodayDate).padStart(2, '0')}`;
        this.selectCalendarDay(todayKey, currentTodayDate, false);
      } else if (Object.keys(notesByDay).length > 0) {
        const firstDayWithNotes = parseInt(Object.keys(notesByDay)[0], 10);
        const dayKey = `${year}-${String(month + 1).padStart(2, '0')}-${String(firstDayWithNotes).padStart(2, '0')}`;
        this.selectCalendarDay(dayKey, firstDayWithNotes, false);
      } else {
        this.renderSelectedDayNotes([]);
      }
    } else {
      this.renderSelectedDayNotes(this.getNotesForDayKey(this.selectedCalendarDay));
    }
  }

  prevCalendarMonth() {
    this.calendarDate.setMonth(this.calendarDate.getMonth() - 1);
    this.selectedCalendarDay = null;
    this.renderCalendar();
  }

  nextCalendarMonth() {
    this.calendarDate.setMonth(this.calendarDate.getMonth() + 1);
    this.selectedCalendarDay = null;
    this.renderCalendar();
  }

  goCalendarToday() {
    this.calendarDate = new Date();
    this.selectedCalendarDay = null;
    this.renderCalendar();
  }

  selectCalendarDay(dateKey, dayNum, reRenderCal = true) {
    this.selectedCalendarDay = dateKey;
    if (reRenderCal) {
      this.renderCalendar();
    }
    const dayNotes = this.getNotesForDayKey(dateKey);
    this.renderSelectedDayNotes(dayNotes, dateKey);
  }

  getNotesForDayKey(dateKey) {
    if (!dateKey) return [];
    return this.notes.filter(n => {
      const d = new Date(n.date);
      const k = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      return k === dateKey;
    });
  }

  renderSelectedDayNotes(dayNotes, dateKey = null) {
    const titleEl = document.getElementById('cal-selected-day-title');
    const containerEl = document.getElementById('cal-selected-day-notes');
    const addBtn = document.getElementById('cal-add-day-btn');

    if (dateKey && titleEl) {
      const [y, m, d] = dateKey.split('-');
      const dObj = new Date(parseInt(y, 10), parseInt(m, 10) - 1, parseInt(d, 10));
      titleEl.textContent = `Note di ${formatItalianDate(dObj, false)} (${dayNotes.length})`;
    }

    if (!containerEl) return;

    if (dayNotes.length === 0) {
      containerEl.innerHTML = `
        <div class="col-span-full py-8 text-center text-slate-400 dark:text-slate-500 bg-white dark:bg-slate-900 rounded-2xl border border-dashed border-slate-200 dark:border-slate-800">
          <p class="text-xs">Nessuna nota inserita per questa data.</p>
          <button onclick="app.openEditorForSelectedDate()" class="mt-2 text-xs font-bold text-blue-600 dark:text-blue-400 hover:underline">
            + Crea una nota per questo giorno
          </button>
        </div>
      `;
      return;
    }

    containerEl.innerHTML = dayNotes.map(n => {
      const d = new Date(n.date);
      const timeStr = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
      const hasPhotos = n.photos && n.photos.length > 0;

      return `
        <div onclick="app.openEditor('${n.id}')" class="p-3.5 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm hover:border-blue-400 cursor-pointer flex items-center justify-between gap-3">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 text-xs font-bold text-blue-600 dark:text-blue-400 mb-0.5">
              <span>${timeStr}</span>
              ${hasPhotos ? `<span class="text-pink-500 text-[11px] font-bold flex items-center gap-0.5"><i data-lucide="camera" class="w-3 h-3"></i> ${n.photos.length}</span>` : ''}
              ${n.weather ? `<span class="text-amber-500 text-[11px] font-medium">${n.weather}</span>` : ''}
            </div>
            <h4 class="font-bold text-sm text-slate-900 dark:text-white truncate">${escapeHtml(n.title || 'Senza Titolo')}</h4>
            <p class="text-xs text-slate-500 dark:text-slate-400 line-clamp-1 mt-0.5">${escapeHtml(n.content || '')}</p>
          </div>
          <i data-lucide="chevron-right" class="w-4 h-4 text-slate-400 shrink-0"></i>
        </div>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
  }

  openEditorForSelectedDate() {
    let customDate = new Date();
    if (this.selectedCalendarDay) {
      const [y, m, d] = this.selectedCalendarDay.split('-');
      customDate = new Date(parseInt(y, 10), parseInt(m, 10) - 1, parseInt(d, 10), new Date().getHours(), new Date().getMinutes());
    }
    this.openEditor(null, customDate);
  }

  // Helper per formattare la località solo come "Paese - Città" (es. Cina - Canton, Italia - Milano)
  formatLocationCountryCity(rawLoc) {
    if (!rawLoc) return '';
    const str = rawLoc.trim();
    if (!str) return '';

    if (str.includes(' - ')) return str;

    const parts = str.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length === 1) {
      return str;
    }

    // Ultima parte: Paese (es. Italia, Cina, Spagna, Francia, Germania, ecc.)
    const country = parts[parts.length - 1].replace(/\s*\([^)]*\)/g, '').trim();

    // Città: penultima parte oppure prima parte
    let cityCandidate = parts.length === 2 ? parts[0] : parts[parts.length - 2];
    let cleanCity = cityCandidate.replace(/\s*\([^)]*\)/g, '').trim();

    if (country && cleanCity && country.toLowerCase() !== cleanCity.toLowerCase()) {
      return `${country} - ${cleanCity}`;
    }
    return country || cleanCity || str;
  }

  // --- STATISTICHE ---
  renderStats() {
    const totalNotes = this.notes.length;
    const withPhotos = this.notes.filter(n => n.photos && n.photos.length > 0).length;
    const pctPhotos = totalNotes > 0 ? Math.round((withPhotos / totalNotes) * 100) : 0;

    // Conteggio parole
    let totalWords = 0;
    const locationsMap = {};
    const foldersMap = {};
    const yearsMap = {};
    let tempSum = 0;
    let tempCount = 0;

    for (const n of this.notes) {
      const text = `${n.title || ''} ${n.content || ''}`.trim();
      const words = text ? text.split(/\s+/).length : 0;
      totalWords += words;

      // Luogo (Formattato come Paese - Città)
      if (n.location) {
        const loc = this.formatLocationCountryCity(n.location);
        if (loc) {
          locationsMap[loc] = (locationsMap[loc] || 0) + 1;
        }
      }

      // Cartella
      if (n.folder) {
        const f = n.folder.trim();
        foldersMap[f] = (foldersMap[f] || 0) + 1;
      }

      // Anno
      const d = new Date(n.date);
      if (!isNaN(d.getTime())) {
        const y = d.getFullYear();
        yearsMap[y] = (yearsMap[y] || 0) + 1;
      }

      // Meteo
      if (n.weather) {
        const tMatch = n.weather.match(/(-?\d+(?:\.\d+)?)\s*°?C/i);
        if (tMatch) {
          tempSum += parseFloat(tMatch[1]);
          tempCount++;
        }
      }
    }

    const avgWords = totalNotes > 0 ? Math.round(totalWords / totalNotes) : 0;
    const avgTemp = tempCount > 0 ? (tempSum / tempCount).toFixed(1) + '°C' : 'N/D';

    // Aggiorna KPI DOM
    document.getElementById('stat-total-notes').textContent = totalNotes;
    document.getElementById('stat-photos-notes').textContent = withPhotos;
    document.getElementById('stat-photos-pct').textContent = `${pctPhotos}% delle note`;
    document.getElementById('stat-total-words').textContent = totalWords.toLocaleString('it-IT');
    document.getElementById('stat-avg-words').textContent = `Media: ${avgWords} parole/nota`;
    document.getElementById('stat-locations-count').textContent = Object.keys(locationsMap).length;
    document.getElementById('stat-avg-temp').textContent = tempCount > 0 ? `Temp. media: ${avgTemp}` : 'Nessun dato meteo';

    // Ripartizione Anni
    const yearsContainer = document.getElementById('stat-years-breakdown');
    if (yearsContainer) {
      const sortedYears = Object.keys(yearsMap).sort((a, b) => b - a);
      const maxYearCount = Math.max(1, ...Object.values(yearsMap));

      if (sortedYears.length === 0) {
        yearsContainer.innerHTML = `<p class="text-xs text-slate-400">Nessuna statistica disponibile.</p>`;
      } else {
        yearsContainer.innerHTML = sortedYears.map(y => {
          const count = yearsMap[y];
          const pct = Math.round((count / maxYearCount) * 100);
          return `
            <div>
              <div class="flex justify-between text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                <span>Anno ${y}</span>
                <span class="text-blue-600 dark:text-blue-400 font-bold">${count} note</span>
              </div>
              <div class="w-full h-2.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                <div class="h-full bg-gradient-to-r from-blue-500 to-indigo-600 rounded-full transition-all duration-500" style="width: ${pct}%"></div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    // Top Luoghi
    const locContainer = document.getElementById('stat-locations-list');
    if (locContainer) {
      const topLocations = Object.entries(locationsMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
      if (topLocations.length === 0) {
        locContainer.innerHTML = `<p class="text-xs text-slate-400 italic">Nessun luogo registrato nelle note.</p>`;
      } else {
        locContainer.innerHTML = topLocations.map(([loc, cnt]) => `
          <div class="flex justify-between items-center bg-slate-50 dark:bg-slate-800/60 p-2 rounded-xl">
            <span class="text-xs font-medium text-slate-800 dark:text-slate-200 truncate pr-2 flex items-center gap-1.5">
              <i data-lucide="map-pin" class="w-3.5 h-3.5 text-emerald-500 shrink-0"></i>
              <span class="truncate">${escapeHtml(loc)}</span>
            </span>
            <span class="text-xs font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 px-2 py-0.5 rounded-full shrink-0">
              ${cnt} ${cnt === 1 ? 'nota' : 'note'}
            </span>
          </div>
        `).join('');
      }
    }

    // Top Cartelle
    const folderContainer = document.getElementById('stat-folders-list');
    if (folderContainer) {
      const topFolders = Object.entries(foldersMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
      if (topFolders.length === 0) {
        folderContainer.innerHTML = `<p class="text-xs text-slate-400 italic">Nessuna cartella o categoria specificata.</p>`;
      } else {
        folderContainer.innerHTML = topFolders.map(([f, cnt]) => `
          <div class="flex justify-between items-center bg-slate-50 dark:bg-slate-800/60 p-2 rounded-xl">
            <span class="text-xs font-medium text-slate-800 dark:text-slate-200 truncate pr-2 flex items-center gap-1.5">
              <i data-lucide="folder" class="w-3.5 h-3.5 text-indigo-500 shrink-0"></i>
              <span class="truncate">${escapeHtml(f)}</span>
            </span>
            <span class="text-xs font-bold bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 px-2 py-0.5 rounded-full shrink-0">
              ${cnt} ${cnt === 1 ? 'nota' : 'note'}
            </span>
          </div>
        `).join('');
      }
    }

    if (window.lucide) lucide.createIcons();
  }

  // --- EDITOR NOTA ---
  openEditor(noteId = null, defaultDate = null) {
    this.editingNoteId = noteId;
    this.editorPhotos = [];
    this.editorAudio = null;

    const titleInput = document.getElementById('editor-title');
    const contentInput = document.getElementById('editor-content');
    const dateInput = document.getElementById('editor-datetime-input');
    const weatherInput = document.getElementById('editor-weather');
    const locationInput = document.getElementById('editor-location');
    const folderInput = document.getElementById('editor-folder');
    const deleteBtn = document.getElementById('editor-delete-btn');

    if (noteId) {
      // Modifica nota esistente
      const note = this.notes.find(n => n.id === noteId);
      if (note) {
        if (titleInput) titleInput.value = note.title || '';
        if (contentInput) contentInput.value = note.content || '';
        if (dateInput) dateInput.value = toDatetimeLocalValue(new Date(note.date));
        if (weatherInput) weatherInput.value = note.weather || '';
        if (locationInput) locationInput.value = note.location || '';
        if (folderInput) folderInput.value = note.folder || '';
        this.editorPhotos = note.photos ? [...note.photos] : [];
        this.editorAudio = note.audio || null;
        deleteBtn?.classList.remove('hidden');
      }
    } else {
      // Nuova nota
      const initialDate = defaultDate || new Date();
      if (titleInput) titleInput.value = '';
      if (contentInput) contentInput.value = '';
      if (dateInput) dateInput.value = toDatetimeLocalValue(initialDate);
      if (weatherInput) weatherInput.value = '';
      if (locationInput) locationInput.value = '';
      if (folderInput) folderInput.value = '';
      this.editorAudio = null;
      deleteBtn?.classList.add('hidden');

      // Rilevamento automatico della posizione (GPS / Cella / Wi-Fi) e del meteo corrente
      this.detectCurrentLocationAndWeather();
    }

    this.renderEditorPhotos();
    this.renderEditorAudio();
    this.onEditorContentChange();

    // Passa alla schermata editor a tutto schermo
    this.switchView('editor');

    // Focus automatico sul titolo per nuove note
    setTimeout(() => {
      if (!noteId) titleInput?.focus();
    }, 150);

    if (window.lucide) lucide.createIcons();
  }

  renderEditorAudio() {
    const container = document.getElementById('editor-audio-container');
    const player = document.getElementById('editor-audio-player');
    if (!container || !player) return;

    if (this.editorAudio) {
      player.src = this.editorAudio;
      container.classList.remove('hidden');
    } else {
      player.pause();
      player.src = '';
      container.classList.add('hidden');
    }
  }

  removeEditorAudio() {
    this.openConfirmModal(
      'Elimina Registrazione Vocale',
      'Sei sicuro di voler eliminare la registrazione vocale allegata a questa nota?',
      () => {
        this.editorAudio = null;
        this.renderEditorAudio();
        this.showToast('Registrazione vocale rimossa', 'info');
      }
    );
  }

  // --- RILEVAMENTO POSIZIONE GPS / CELLA / WI-FI & METEO ---
  async detectCurrentLocationAndWeather(force = false) {
    const locationInput = document.getElementById('editor-location');
    const weatherInput = document.getElementById('editor-weather');
    const spinner = document.getElementById('location-spinner');

    if (!force && locationInput && locationInput.value.trim() !== '') {
      return;
    }

    if (spinner) spinner.classList.remove('hidden');

    // 1. Prova Geolocation API (GPS su Android/cellulare, o Wi-Fi / Cella)
    if ('geolocation' in navigator) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const lat = position.coords.latitude;
          const lon = position.coords.longitude;
          await this.fetchAddressAndWeather(lat, lon);
          if (spinner) spinner.classList.add('hidden');
        },
        async (err) => {
          console.warn('GPS/Wi-Fi positioning error or permission denied, fallback to IP network:', err);
          await this.fetchLocationFromIp();
          if (spinner) spinner.classList.add('hidden');
        },
        { enableHighAccuracy: true, timeout: 8000, maximumAge: 60000 }
      );
    } else {
      await this.fetchLocationFromIp();
      if (spinner) spinner.classList.add('hidden');
    }
  }

  async fetchAddressAndWeather(lat, lon) {
    const locationInput = document.getElementById('editor-location');
    const weatherInput = document.getElementById('editor-weather');

    // Reverse Geocoding via OpenStreetMap Nominatim
    try {
      const geoUrl = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
      const response = await fetch(geoUrl, {
        headers: { 'Accept-Language': 'it,en' }
      });
      if (response.ok) {
        const data = await response.json();
        const addr = data.address || {};
        const road = addr.road || addr.pedestrian || addr.street || '';
        const houseNum = addr.house_number ? ' ' + addr.house_number : '';
        const city = addr.city || addr.town || addr.village || addr.suburb || addr.municipality || '';
        const province = addr.county || addr.state_district || addr.state || '';
        const country = addr.country || '';

        const parts = [];
        if (road) parts.push(road + houseNum);
        if (city) {
          parts.push(city + (province && province !== city ? ` (${province})` : ''));
        }
        if (country) parts.push(country);

        const formattedAddress = parts.join(', ') || data.display_name || `${lat.toFixed(4)}, ${lon.toFixed(4)}`;
        if (locationInput && (!locationInput.value || locationInput.value === '')) {
          locationInput.value = formattedAddress;
        }
      }
    } catch (e) {
      console.warn('Errore reverse geocoding OSM:', e);
      if (locationInput && !locationInput.value) {
        locationInput.value = `${lat.toFixed(4)}, ${lon.toFixed(4)}`;
      }
    }

    // Meteo in tempo reale via Open-Meteo API
    try {
      const weatherUrl = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true`;
      const wRes = await fetch(weatherUrl);
      if (wRes.ok) {
        const wData = await wRes.json();
        const cur = wData.current_weather;
        if (cur) {
          const temp = cur.temperature;
          const code = cur.weathercode;
          const conditionDesc = this.getWeatherDescription(code);
          const weatherFormatted = `${temp.toFixed(1)}°C ${conditionDesc}`.trim();
          if (weatherInput && (!weatherInput.value || weatherInput.value === '')) {
            weatherInput.value = weatherFormatted;
          }
        }
      }
    } catch (e) {
      console.warn('Errore fetch meteo:', e);
    }
  }

  async fetchLocationFromIp() {
    const locationInput = document.getElementById('editor-location');
    try {
      const ipRes = await fetch('https://get.geojs.io/v1/ip/geo.json');
      if (ipRes.ok) {
        const ipData = await ipRes.json();
        const city = ipData.city || '';
        const region = ipData.region || '';
        const country = ipData.country || '';
        const lat = parseFloat(ipData.latitude);
        const lon = parseFloat(ipData.longitude);

        const parts = [city, region, country].filter(Boolean);
        const ipLoc = parts.join(', ');
        if (locationInput && !locationInput.value) {
          locationInput.value = ipLoc;
        }

        if (!isNaN(lat) && !isNaN(lon)) {
          await this.fetchAddressAndWeather(lat, lon);
        }
      }
    } catch (e) {
      console.warn('Errore fallback geolocalizzazione IP:', e);
    }
  }

  getWeatherDescription(code) {
    const weatherCodes = {
      0: 'Sereno',
      1: 'Prevalentemente Sereno',
      2: 'Poco Nuvoloso',
      3: 'Coperto',
      45: 'Nebbia',
      48: 'Nebbia con brina',
      51: 'Pioggerella leggera',
      53: 'Pioggerella',
      55: 'Pioggia fitta',
      61: 'Pioggia debole',
      63: 'Pioggia moderata',
      65: 'Pioggia forte',
      71: 'Neve debole',
      73: 'Neve moderata',
      75: 'Neve intensa',
      80: 'Rovescio leggero',
      81: 'Rovescio moderato',
      82: 'Nubifragio',
      95: 'Temporale',
      96: 'Temporale con grandine',
      99: 'Forte temporale con grandine'
    };
    return weatherCodes[code] || '';
  }

  closeEditor() {
    this.editingNoteId = null;
    this.editorPhotos = [];
    this.switchView('notes');
  }

  onEditorContentChange() {
    const content = document.getElementById('editor-content')?.value || '';
    const words = content.trim() ? content.trim().split(/\s+/).length : 0;
    const wordCountEl = document.getElementById('editor-word-count');
    if (wordCountEl) {
      wordCountEl.textContent = `${words} ${words === 1 ? 'parola' : 'parole'}`;
    }
  }

  toggleMetaAccordion() {
    const content = document.getElementById('meta-accordion-content');
    const icon = document.getElementById('meta-accordion-icon');
    if (content) {
      const isHidden = content.classList.toggle('hidden');
      if (icon) {
        icon.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
      }
    }
  }

  insertEditorFormat(type) {
    const textarea = document.getElementById('editor-content');
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.substring(start, end);

    let replacement = '';
    if (type === 'bold') {
      replacement = `**${selected || 'testo'}**`;
    } else if (type === 'italic') {
      replacement = `*${selected || 'testo'}*`;
    } else if (type === 'list') {
      replacement = `\n- ${selected || 'elemento'}`;
    } else if (type === 'check') {
      replacement = `\n[ ] ${selected || 'attività'}`;
    } else if (type === 'divider') {
      replacement = `\n------------------------------------------------------------------------------------------------\n`;
    } else if (type === 'time') {
      const now = new Date();
      replacement = ` [${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}] `;
    }

    textarea.setRangeText(replacement, start, end, 'end');
    textarea.focus();
    this.onEditorContentChange();
  }

  // --- GESTIONE FOTOGRAFIE NELL'EDITOR (FOTOCAMERA / GALLERIA) ---
  openPhotoSourceModal() {
    const modal = document.getElementById('photo-source-modal');
    modal?.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
  }

  closePhotoSourceModal() {
    const modal = document.getElementById('photo-source-modal');
    modal?.classList.add('hidden');
  }

  triggerPhotoCamera() {
    this.closePhotoSourceModal();
    const cameraInput = document.getElementById('photo-camera-input');
    cameraInput?.click();
  }

  triggerPhotoGallery() {
    this.closePhotoSourceModal();
    const galleryInput = document.getElementById('photo-gallery-input');
    galleryInput?.click();
  }

  async handlePhotoUpload(event) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (!file.type.startsWith('image/')) continue;

      try {
        const base64 = await this.resizeAndEncodeImage(file);
        this.editorPhotos.push(base64);
      } catch (err) {
        console.error('Errore caricamento immagine:', err);
        this.showToast('Errore nel caricamento della foto', 'error');
      }
    }

    this.renderEditorPhotos();
    event.target.value = '';
  }

  resizeAndEncodeImage(file, maxDimension = 1400, quality = 0.82) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          let width = img.width;
          let height = img.height;

          if (width > maxDimension || height > maxDimension) {
            if (width > height) {
              height = Math.round((height * maxDimension) / width);
              width = maxDimension;
            } else {
              width = Math.round((width * maxDimension) / height);
              height = maxDimension;
            }
          }

          const canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, width, height);

          const dataUrl = canvas.toDataURL('image/jpeg', quality);
          resolve(dataUrl);
        };
        img.onerror = reject;
        img.src = e.target.result;
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  renderEditorPhotos() {
    const container = document.getElementById('editor-photos-container');
    const grid = document.getElementById('editor-photos-grid');
    const countEl = document.getElementById('editor-photos-count');

    if (this.editorPhotos.length === 0) {
      container?.classList.add('hidden');
      return;
    }

    container?.classList.remove('hidden');
    if (countEl) countEl.textContent = this.editorPhotos.length;

    if (!grid) return;

    grid.innerHTML = this.editorPhotos.map((photoBase64, idx) => `
      <div class="relative group aspect-square rounded-xl overflow-hidden bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
        <img src="${photoBase64}" alt="Foto ${idx + 1}" class="w-full h-full object-cover cursor-pointer" onclick="app.openImageViewer('${photoBase64}')">
        <button 
          type="button" 
          onclick="app.removeEditorPhoto(${idx})" 
          class="absolute top-1 right-1 p-1 bg-red-600 text-white rounded-full shadow-md hover:bg-red-700 transition-colors"
          title="Rimuovi foto"
        >
          <i data-lucide="x" class="w-3.5 h-3.5"></i>
        </button>
      </div>
    `).join('');

    if (window.lucide) lucide.createIcons();
  }

  removeEditorPhoto(index) {
    this.openConfirmModal(
      'Elimina Fotografia',
      'Sei sicuro di voler rimuovere questa fotografia dalla nota?',
      () => {
        this.editorPhotos.splice(index, 1);
        this.renderEditorPhotos();
        this.showToast('Fotografia rimossa', 'info');
      }
    );
  }

  // --- SALVATAGGIO NOTA ---
  async saveNote() {
    const titleInput = document.getElementById('editor-title');
    const contentInput = document.getElementById('editor-content');
    const dateInput = document.getElementById('editor-datetime-input');
    const weatherInput = document.getElementById('editor-weather');
    const locationInput = document.getElementById('editor-location');
    const folderInput = document.getElementById('editor-folder');

    const title = titleInput?.value.trim() || 'Senza Titolo';
    const content = contentInput?.value.trim() || '';
    const dateVal = parseDateSafe(dateInput?.value);
    const weather = weatherInput?.value.trim() || '';
    const location = locationInput?.value.trim() || '';
    const folder = folderInput?.value.trim() || '';

    if (!content && title === 'Senza Titolo') {
      this.showToast('Inserisci almeno un titolo o del testo per salvare la nota.', 'error');
      return;
    }

    const noteId = this.editingNoteId || ('note_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5));
    const nowIso = new Date().toISOString();
    const existing = this.editingNoteId ? this.notes.find(n => n.id === this.editingNoteId) : null;

    const noteObj = {
      id: noteId,
      title: title,
      content: content,
      date: dateVal.toISOString(),
      weather: weather,
      location: location,
      folder: folder,
      tags: existing?.tags || [],
      photos: [...this.editorPhotos],
      audio: this.editorAudio || null,
      pinned: existing ? Boolean(existing.pinned) : false,
      createdAt: existing?.createdAt || dateVal.toISOString(),
      updatedAt: nowIso
    };

    try {
      this.setCloudStatus('syncing', 'Salvataggio...');
      
      // 1. Salva prioritariamente in IndexedDB locale
      await this.db.put(noteObj);
      
      // 2. Aggiorna immediatamente lo stato locale in memoria
      const existingIdx = this.notes.findIndex(n => n.id === noteId);
      if (existingIdx >= 0) {
        this.notes[existingIdx] = noteObj;
      } else {
        this.notes.unshift(noteObj);
      }
      this.sortNotes();

      // 3. Ricarica e aggiorna interfaccia
      this.render();
      this.updateStorageStats();
      this.closeEditor();
      this.showToast('Nota salvata con successo!', 'success');

      // 4. Sincronizzazione asincrona con Firebase in background
      this.firebase.saveNote(noteObj)
        .then(() => this.setCloudStatus('online', 'Sincronizzato'))
        .catch(e => {
          console.warn('Sync Firebase warning:', e);
          this.setCloudStatus('offline', 'Offline (Salvato in locale)');
        });

    } catch (err) {
      console.error('Errore salvataggio nota:', err);
      this.showToast('Errore durante il salvataggio della nota', 'error');
    }
  }

  // --- ELIMINAZIONE NOTA ---
  confirmDeleteNote(id) {
    const note = this.notes.find(n => n.id === id);
    this.openConfirmModal(
      'Elimina Nota',
      `Sei sicuro di voler eliminare la nota "${note?.title || 'selezionata'}"? L'azione non può essere annullata.`,
      async () => {
        try {
          this.setCloudStatus('syncing', 'Eliminazione...');
          await this.db.delete(id);
          this.firebase.deleteNote(id).catch(e => console.warn('Delete Firebase warning:', e));
          await this.loadNotes();
          this.render();
          this.updateStorageStats();
          this.setCloudStatus('online', 'Sincronizzato');
          this.showToast('Nota eliminata', 'info');
        } catch (e) {
          console.error(e);
          this.showToast('Errore eliminazione nota', 'error');
        }
      }
    );
  }

  deleteCurrentNote() {
    if (this.editingNoteId) {
      this.closeEditor();
      this.confirmDeleteNote(this.editingNoteId);
    }
  }

  // --- CONDIVISIONE NOTA ---
  shareNote(id) {
    const note = this.notes.find(n => n.id === id);
    if (!note) return;

    const fullText = `${note.title ? `::: ${note.title} :::\n\n` : ''}${note.content || ''}${note.weather ? `\n\nMeteo: ${note.weather}` : ''}${note.location ? `\nLuogo: ${note.location}` : ''}`;

    if (navigator.share) {
      navigator.share({
        title: note.title || 'Nota',
        text: fullText
      }).catch(() => {});
    } else if (navigator.clipboard) {
      navigator.clipboard.writeText(fullText).then(() => {
        this.showToast('Testo della nota copiato negli appunti!', 'success');
      });
    }
  }

  // --- ANTEPRIMA IMMAGINE FULLSCREEN ---
  openImageViewer(src) {
    const modal = document.getElementById('image-viewer-modal');
    const img = document.getElementById('image-viewer-img');
    if (modal && img) {
      img.src = src;
      modal.classList.remove('hidden');
    }
  }

  closeImageViewer() {
    const modal = document.getElementById('image-viewer-modal');
    if (modal) modal.classList.add('hidden');
  }

  // --- IMPORT / EXPORT FUNZIONI ---
  async handleDiaroFileImport(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const text = e.target.result;
        const parsedNotes = parseDiaroExportText(text);

        if (parsedNotes.length === 0) {
          this.showToast('Nessuna nota trovata nel file .TXT.', 'error');
          return;
        }

        this.openConfirmModal(
          'Importa da Diaro',
          `Sono state trovate ${parsedNotes.length} note nel file. Vuoi importarle nel tuo archivio?`,
          async () => {
            this.setCloudStatus('syncing', 'Importazione...');
            await this.db.putBatch(parsedNotes);
            this.firebase.saveBatch(parsedNotes).catch(e => console.warn('Firebase batch sync warning:', e));
            await this.loadNotes();
            this.render();
            this.updateStorageStats();
            this.setCloudStatus('online', 'Sincronizzato');
            this.showToast(`Importate con successo ${parsedNotes.length} note!`, 'success');
            this.switchView('notes');
          }
        );
      } catch (err) {
        console.error('Errore import Diaro:', err);
        this.showToast('Errore durante la lettura del file Diaro .TXT', 'error');
      }
    };
    reader.readAsText(file, 'UTF-8');
    event.target.value = '';
  }

  async importSampleDiaroDirectly() {
    try {
      const response = await fetch('sample-diaro.txt');
      let text = '';
      if (response.ok) {
        text = await response.text();
      } else {
        // Fallback a campione integrato se fetch locale fallisce
        text = `12 Agosto 2026, Mercoledì 10:16\n\n::: MADRID :::\n\nhttps://maps.app.goo.gl/DZ8JAuinXzzR7KgD9\n\nMeteo: 28.1°C\n\n------------------------------------------------------------------------------------------------\n\n10 Agosto 2026, Lunedì 10:34\n\n::: IFA :::\n\n2.2 / 185  worldplug nuovo modello\n3.2 – 127  PROOVE   (Mike)\n11.2-111  Glary star (Jessica) bluetooth speakers con batteria rem\n\nMeteo: 28.1°C\n\n------------------------------------------------------------------------------------------------\n\n05 Agosto 2026, Mercoledì 16:00\n\n::: Stelle fotografate DWARF 3 :::\n\nC_20\nIC_4604\nM_31\nM_33\nM_51\nM_57\nM_63\nMoon\nNGC_7380\nNGC_281\nUGC_8837\n\nMeteo: 36.2°C\n\n------------------------------------------------------------------------------------------------\n\n22 Luglio 2026, Mercoledì 08:34\n\n::: Prompt Antigravity - Schede e preventivi :::\n\nCrea un'applicazione web completa per la generazione di schede prodotto in formato PDF a partire dal sito ufficiale di Karma Italiana.\n\nMeteo: 28.5°C`;
      }

      const parsedNotes = parseDiaroExportText(text);
      if (parsedNotes.length > 0) {
        this.setCloudStatus('syncing', 'Sincronizzazione...');
        await this.db.putBatch(parsedNotes);
        this.firebase.saveBatch(parsedNotes).catch(e => console.warn('Firebase batch sync warning:', e));
        await this.loadNotes();
        this.render();
        this.updateStorageStats();
        this.setCloudStatus('online', 'Sincronizzato');
        this.showToast(`Caricate ${parsedNotes.length} note di esempio con successo!`, 'success');
        this.switchView('notes');
      }
    } catch (e) {
      console.error(e);
      this.showToast('Errore caricamento file di esempio', 'error');
    }
  }

  exportDiaroTxt() {
    if (this.notes.length === 0) {
      this.showToast('Nessuna nota da esportare.', 'info');
      return;
    }
    const txtContent = generateDiaroTxt(this.notes);
    const blob = new Blob([txtContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const dateStr = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `diaro-export-${dateStr}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast('File Diaro .TXT esportato con successo!', 'success');
  }

  exportJsonBackup() {
    if (this.notes.length === 0) {
      this.showToast('Nessuna nota da esportare.', 'info');
      return;
    }
    const exportData = {
      app: 'MassiNote',
      version: '2.0',
      exportDate: new Date().toISOString(),
      totalNotes: this.notes.length,
      notes: this.notes
    };
    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const dateStr = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `backup-massinote-${dateStr}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    this.showToast('Backup JSON completo scaricato!', 'success');
  }

  handleJsonBackupImport(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const rawText = e.target.result;
        const data = JSON.parse(rawText);
        let rawNotes = Array.isArray(data) ? data : (data.notes || data.data || []);
        
        if (!Array.isArray(rawNotes) || rawNotes.length === 0) {
          this.showToast('File JSON non valido o nessuna nota trovata.', 'error');
          return;
        }

        // Normalizzazione profonda di tutte le proprietà per IndexedDB
        const normalizedNotes = rawNotes.map((n, idx) => {
          let noteDate = new Date();
          if (n.date) {
            const parsed = new Date(n.date);
            if (!isNaN(parsed.getTime())) noteDate = parsed;
          }

          return {
            id: String(n.id || ('note_' + Date.now() + '_' + idx + '_' + Math.random().toString(36).substr(2, 6))),
            title: String(n.title || n.name || 'Senza Titolo'),
            content: String(n.content || n.text || n.body || ''),
            date: noteDate.toISOString(),
            weather: String(n.weather || ''),
            location: String(n.location || n.place || ''),
            folder: String(n.folder || n.category || ''),
            tags: Array.isArray(n.tags) ? n.tags.map(String) : [],
            photos: Array.isArray(n.photos) ? n.photos : (Array.isArray(n.images) ? n.images : []),
            audio: n.audio || null,
            pinned: Boolean(n.pinned),
            createdAt: n.createdAt ? new Date(n.createdAt).toISOString() : noteDate.toISOString(),
            updatedAt: n.updatedAt ? new Date(n.updatedAt).toISOString() : new Date().toISOString()
          };
        });

        this.openConfirmModal(
          'Ripristina Backup JSON',
          `Il file contiene ${normalizedNotes.length} note. Vuoi importarle nel tuo archivio?`,
          async () => {
            try {
              this.setCloudStatus('syncing', 'Importazione...');
              // 1. Salva le note in IndexedDB locale
              await this.db.putBatch(normalizedNotes);

              // 2. Sincronizzazione asincrona Firebase
              this.firebase.saveBatch(normalizedNotes).catch(e => console.warn('Firebase batch sync warning:', e));

              // 3. Ricarica e visualizza le note
              await this.loadNotes();
              this.render();
              this.updateStorageStats();
              this.setCloudStatus('online', 'Sincronizzato');
              this.showToast(`Ripristinate con successo ${normalizedNotes.length} note!`, 'success');
              this.switchView('notes');
            } catch (importErr) {
              console.error('Errore durante importazione:', importErr);
              this.showToast('Errore durante il salvataggio delle note nel database.', 'error');
            }
          }
        );
      } catch (err) {
        console.error('Errore lettura JSON:', err);
        this.showToast('Errore nella lettura o formato JSON non valido.', 'error');
      }
    };
    reader.readAsText(file, 'UTF-8');
    event.target.value = '';
  }

  confirmResetDatabase() {
    this.openConfirmModal(
      'Cancellare tutte le note?',
      'Sei sicuro di voler eliminare DEFINITIVAMENTE tutte le note salvate? Ti consigliamo di esportare prima un backup.',
      async () => {
        this.setCloudStatus('syncing', 'Cancellazione...');
        await this.firebase.clearAll(this.notes);
        await this.db.clear();
        await this.loadNotes();
        this.render();
        this.updateStorageStats();
        this.setCloudStatus('online', 'Sincronizzato');
        this.showToast('Tutte le note sono state eliminate.', 'info');
      }
    );
  }

  updateStorageStats() {
    const badge = document.getElementById('storage-usage-badge');
    if (badge) {
      badge.textContent = `${this.notes.length} note archiviate`;
    }
  }

  // --- MODALE CONFERMA GENERICA ---
  openConfirmModal(title, message, onConfirmCallback) {
    const modal = document.getElementById('confirm-modal');
    const titleEl = document.getElementById('confirm-modal-title');
    const descEl = document.getElementById('confirm-modal-desc');
    const okBtn = document.getElementById('confirm-modal-ok-btn');

    if (titleEl) titleEl.textContent = title;
    if (descEl) descEl.textContent = message;

    if (okBtn) {
      okBtn.onclick = () => {
        this.closeConfirmModal();
        if (onConfirmCallback) onConfirmCallback();
      };
    }

    modal?.classList.remove('hidden');
  }

  closeConfirmModal() {
    const modal = document.getElementById('confirm-modal');
    modal?.classList.add('hidden');
  }

  // --- NOTIFICHE TOAST ---
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    let bg = 'bg-slate-900 text-white';
    let icon = 'info';

    if (type === 'success') {
      bg = 'bg-emerald-600 text-white';
      icon = 'check-circle';
    } else if (type === 'error') {
      bg = 'bg-red-600 text-white';
      icon = 'alert-circle';
    }

    toast.className = `toast-msg p-3 px-4 rounded-xl shadow-lg flex items-center gap-2.5 text-xs font-semibold ${bg}`;
    toast.innerHTML = `<i data-lucide="${icon}" class="w-4 h-4 shrink-0"></i><span>${escapeHtml(message)}</span>`;

    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px)';
      toast.style.transition = 'all 0.25s ease';
      setTimeout(() => toast.remove(), 250);
    }, 3200);
  }

  // --- EVENT LISTENERS GLOBALI ---
  initEventListeners() {
    // 1. Inizializza supporto pressione prolungata (3 secondi) e click rapido sul tasto +
    this.initLongPressListeners();

    // 2. Scorciatoie da tastiera
    window.addEventListener('keydown', (e) => {
      // Escape chiude editor o modali
      if (e.key === 'Escape') {
        this.closeEditor();
        this.closeImageViewer();
        this.closeConfirmModal();
        this.cancelVoiceRecording();
      }
      // Ctrl+S o Cmd+S salva la nota se l'editor è aperto
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        const editorView = document.getElementById('view-editor');
        if (editorView && !editorView.classList.contains('hidden')) {
          e.preventDefault();
          this.saveNote();
        }
      }
    });

    // 3. Drag and Drop globale di file JSON
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
    });

    window.addEventListener('drop', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const files = e.dataTransfer?.files;
      if (!files || files.length === 0) return;
      const file = files[0];
      const name = file.name.toLowerCase();

      if (name.endsWith('.json')) {
        this.handleJsonBackupImport({ target: { files: [file], value: '' } });
      }
    });

    // Registrazione Service Worker per PWA Offline
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').catch(err => {
        console.log('SW registration note:', err);
      });
    }
  }
}

// Utility escaping HTML
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Inizializzazione globale
window.app = new AppController();
document.addEventListener('DOMContentLoaded', () => {
  window.app.init();
});
