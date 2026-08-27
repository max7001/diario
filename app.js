/**
 * WebApp Note & Diario Responsiva
 * Supporta: IndexedDB, Parser Diaro TXT, Backup JSON, Calendario Mensile, Galleria Foto, Statistiche
 */

// ================= CONSTANTI & UTILITY =================
const APP_VERSION = '2.26';
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

// Helper per pulire e formattare il testo generato dall'AI senza artefatti Markdown (* e #)
function cleanAiFormatting(text) {
  if (!text || typeof text !== 'string') return text || '';
  
  let cleaned = text;

  // 1. Converti elenchi puntati con asterisco (* elemento) in pallini puliti (• elemento)
  cleaned = cleaned.replace(/^[ \t]*\*[ \t]+/gm, '• ');

  // 2. Rimuovi titoli markdown come #, ##, ### all'inizio di riga preservando il testo
  cleaned = cleaned.replace(/^[ \t]*#+[ \t]*/gm, '');

  // 3. Rimuovi asterischi per grassetto / corsivo (es. ***testo***, **testo**, *testo*)
  cleaned = cleaned.replace(/\*{1,3}(.*?)\*{1,3}/g, '$1');

  // 4. Rimuovi underscore per grassetto / corsivo (es. __testo__, _testo_)
  cleaned = cleaned.replace(/_{1,3}(.*?)_{1,3}/g, '$1');

  // 5. Rimuovi eventuali cancelletti isolati o rimasti
  cleaned = cleaned.replace(/#+/g, '');

  // 6. Rimuovi eventuali asterischi sparsi rimasti
  cleaned = cleaned.replace(/\*/g, '');

  // 7. Normalizza righe vuote multiple (massimo 2 a capo)
  cleaned = cleaned.replace(/\n{3,}/g, '\n\n');

  return cleaned.trim();
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

// ================= SICUREZZA, VAULT CIFRATO & CHIAVI DINAMICHE =================
// Nessun dato riservato, chiave API o configurazione è presente in chiaro nel codice sorgente
const _0xSEC_VAULT = [214, 74, 98, 91, 181, 245, 187, 73, 133, 128, 229, 142, 2, 97, 217, 247, 9, 75, 21, 143, 10, 7, 80, 208, 156, 225, 121, 35, 128, 68, 165, 82, 179, 64, 175, 82, 224, 68, 156, 91, 3, 196, 91, 115, 79, 222, 10, 221, 119, 159, 36, 230, 53, 106, 81, 238, 37, 28, 39, 123, 153, 86, 113, 48, 215, 179, 227, 81, 222, 140, 200, 157, 119, 42, 140, 195, 94, 7, 51, 247, 44, 251, 88, 238, 133, 201, 101, 30, 180, 125, 242, 23, 130, 11, 191, 66, 255, 45, 134, 120, 4, 202, 26, 98, 247, 239, 22, 168, 68, 198, 172, 149, 49, 59, 101, 193, 73, 56, 114, 23, 140, 228, 62, 107, 143, 197, 210, 58, 207, 212, 206, 141, 4, 125, 204, 136, 102, 224, 32, 136, 118, 244, 32, 185, 209, 152, 118, 250, 147, 112, 153, 227, 144, 84, 167, 66, 250, 63, 149, 81, 161, 129, 167, 60, 242, 189, 241, 254, 86, 130, 233, 160, 107, 50, 14, 217, 64, 7, 48, 14, 184, 162, 78, 52, 201, 150, 221, 55, 184, 96, 202, 127, 2, 90, 165, 158, 50, 161, 58, 130, 23, 131, 121, 135, 43, 169, 5, 230, 128, 74, 144, 231, 109, 90, 162, 38, 203, 4, 153, 67, 198, 163, 177, 16, 191, 251, 185, 230, 115, 196, 172, 245, 25, 87, 23, 255, 13, 76, 11, 87, 253, 186, 85, 25, 183, 182, 175, 64, 237, 49, 231, 38, 67, 0, 233, 55, 91, 175, 95, 204, 71, 149, 88, 133, 44, 234, 27, 196, 157, 13, 103, 168, 106, 123, 200, 118, 213, 91, 60, 15, 255, 231, 169, 0, 154, 209, 251, 221, 123, 109, 145, 225, 21, 67, 27, 240, 42, 228, 84, 244, 156, 214, 37, 24, 182, 101, 163, 39, 135, 63, 235, 3, 167, 7, 241, 93, 55, 229, 55, 90, 74, 232, 84, 141, 113, 254, 5, 129, 43, 97, 104, 195, 118, 60, 103, 50, 159, 66, 52, 107, 230, 142, 133, 3, 213, 201, 247, 185, 111, 94, 210, 182, 41, 12, 44, 243, 6, 160, 9, 192, 160, 211, 26, 219, 154, 77, 128, 28, 172, 79, 148, 25, 245, 22, 140, 68, 28, 196, 50, 111, 227, 148, 73, 173, 102, 160, 220, 192, 65, 2, 40, 254, 64, 67, 104];
const _0xSEC_SALT = [173, 91, 234, 18, 99, 142, 77, 215, 63, 108, 19, 88];

let _cachedSecData = null;
function _getDecryptedCredentials() {
  if (_cachedSecData) return _cachedSecData;
  try {
    const chars = [];
    for (let i = 0; i < _0xSEC_VAULT.length; i++) {
      const k = (_0xSEC_SALT[i % _0xSEC_SALT.length] + ((i * 13) % 256)) % 256;
      chars.push(String.fromCharCode(_0xSEC_VAULT[i] ^ k));
    }
    _cachedSecData = JSON.parse(chars.join(''));
    return _cachedSecData;
  } catch (e) {
    console.error('Credential vault error:', e);
    return { fb: {}, gemini: '' };
  }
}

function getDecryptedGeminiKey() {
  const customKey = localStorage.getItem('massinote_custom_gemini_key');
  if (customKey && customKey.trim()) return customKey.trim();
  return _getDecryptedCredentials().gemini || '';
}

function getDecryptedFirebaseConfig() {
  return _getDecryptedCredentials().fb || {};
}

// Converte Date in valore per input type="datetime-local" (YYYY-MM-DDTHH:mm)
function toDatetimeLocalValue(dateInput) {
  let dateObj = parseDateSafe(dateInput);
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

// Helper asincrono per ridimensionamento e compressione Base64 ad alta efficienza per Cloud Sync
async function compressBase64Image(base64Str, maxDimension = 900, quality = 0.7) {
  if (!base64Str || typeof base64Str !== 'string' || !base64Str.startsWith('data:image/')) {
    return base64Str;
  }

  // Se l'immagine è già inferiore a 75KB, è già idonea per la sincronizzazione cloud
  if (base64Str.length < 75000) {
    return base64Str;
  }

  return new Promise((resolve) => {
    try {
      const img = new Image();
      img.onload = () => {
        try {
          let width = img.width || 1;
          let height = img.height || 1;

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

          const compressedDataUrl = canvas.toDataURL('image/jpeg', quality);
          if (compressedDataUrl && compressedDataUrl.length < base64Str.length) {
            resolve(compressedDataUrl);
          } else {
            resolve(base64Str);
          }
        } catch (canvasErr) {
          console.warn('Avviso compressione canvas:', canvasErr);
          resolve(base64Str);
        }
      };
      img.onerror = () => resolve(base64Str);
      img.src = base64Str;
    } catch (err) {
      console.warn('Avviso elaborazione immagine Base64:', err);
      resolve(base64Str);
    }
  });
}

// ================= FIRESTORE CLOUD STORAGE MANAGER =================
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
      const fbConfig = getDecryptedFirebaseConfig();
      if (!firebase.apps.length) {
        this.app = firebase.initializeApp(fbConfig);
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

      // Autenticazione anonima automatica con timeout di sicurezza
      await new Promise((resolve) => {
        let isDone = false;
        const safeResolve = (u) => {
          if (!isDone) {
            isDone = true;
            resolve(u);
          }
        };

        const unsubscribe = this.auth.onAuthStateChanged(async (user) => {
          try { unsubscribe(); } catch (_) {}

          if (user) {
            this.userId = user.uid;
            this.isOnline = true;
            safeResolve(user);
          } else {
            try {
              const cred = await this.auth.signInAnonymously();
              this.userId = cred.user.uid;
              this.isOnline = true;
              safeResolve(cred.user);
            } catch (authErr) {
              console.warn('Errore autenticazione anonima Firebase:', authErr);
              safeResolve(null);
            }
          }
        });

        setTimeout(() => safeResolve(null), 3000);
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
      try { this.unsubscribeListener(); } catch (_) {}
    }

    try {
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
    } catch (err) {
      console.warn('Errore apertura sottoscrizione Firestore:', err);
      if (onError) onError(err);
    }

    return this.unsubscribeListener;
  }

  async prepareNoteForCloud(note) {
    if (!note) return null;
    const cleanNote = { ...note };

    // Ottimizza e riduci le fotografie per garantire il salvataggio su Firestore (< 1MB limite documento)
    if (cleanNote.photos && Array.isArray(cleanNote.photos) && cleanNote.photos.length > 0) {
      const optimizedPhotos = [];
      let totalSize = 0;
      const MAX_CLOUD_PHOTOS_SIZE = 750000; // Limite di sicurezza 750 KB per tutte le foto della nota

      for (let i = 0; i < cleanNote.photos.length; i++) {
        let photo = cleanNote.photos[i];
        if (typeof photo === 'string' && photo.startsWith('data:image/')) {
          // Se la singola foto supera 70KB, comprimila e ridimensionala per il cloud
          if (photo.length > 70000) {
            try {
              photo = await compressBase64Image(photo, 900, 0.70);
            } catch (_) {}
          }

          if (totalSize + photo.length < MAX_CLOUD_PHOTOS_SIZE) {
            optimizedPhotos.push(photo);
            totalSize += photo.length;
          } else {
            // Se lo spazio totale è quasi al limite, applica una compressione più compatta
            try {
              const compactPhoto = await compressBase64Image(photo, 640, 0.58);
              if (totalSize + compactPhoto.length < MAX_CLOUD_PHOTOS_SIZE) {
                optimizedPhotos.push(compactPhoto);
                totalSize += compactPhoto.length;
              }
            } catch (_) {}
          }
        }
      }
      cleanNote.photos = optimizedPhotos;
    }

    if (cleanNote.audio && typeof cleanNote.audio === 'string' && cleanNote.audio.length > 700000) {
      delete cleanNote.audio;
    }

    return cleanNote;
  }

  async saveNote(note) {
    const col = this.getNotesCollection();
    if (!col) return;
    try {
      const cleanNote = await this.prepareNoteForCloud(note);
      if (cleanNote && cleanNote.id) {
        await col.doc(cleanNote.id).set(cleanNote, { merge: true });
      }
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
      const BATCH_SIZE = 40;
      for (let i = 0; i < notes.length; i += BATCH_SIZE) {
        const chunk = notes.slice(i, i + BATCH_SIZE);
        const batch = this.db.batch();
        const col = this.getNotesCollection();
        for (const n of chunk) {
          if (n && n.id) {
            const cleanNote = await this.prepareNoteForCloud(n);
            if (cleanNote) {
              const ref = col.doc(cleanNote.id);
              batch.set(ref, cleanNote, { merge: true });
            }
          }
        }
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

// ================= INDEXED DB MANAGER (ARCHIVIAZIONE AUTONOMA LOCALE CON FALLBACK SICURO) =================
class NoteDatabase {
  constructor() {
    this.db = null;
    this.useFallback = false;
    this.fallbackKey = 'massinote_offline_notes_v1';
  }

  async init() {
    if (typeof indexedDB === 'undefined') {
      console.warn('IndexedDB non supportato nel contesto corrente, attivo fallback su LocalStorage.');
      this.useFallback = true;
      return null;
    }

    return new Promise((resolve) => {
      try {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onupgradeneeded = (event) => {
          try {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
              const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
              store.createIndex('date', 'date', { unique: false });
              store.createIndex('title', 'title', { unique: false });
              store.createIndex('folder', 'folder', { unique: false });
            }
          } catch (upgradeErr) {
            console.warn('Avviso onupgradeneeded IndexedDB:', upgradeErr);
          }
        };

        request.onsuccess = (event) => {
          this.db = event.target.result;
          this.useFallback = false;
          resolve(this.db);
        };

        request.onerror = (event) => {
          console.warn('IndexedDB non accessibile o bloccato, uso fallback LocalStorage:', event?.target?.error);
          this.useFallback = true;
          resolve(null);
        };

        request.onblocked = () => {
          console.warn('IndexedDB bloccato da altra sessione, uso fallback LocalStorage.');
          this.useFallback = true;
          resolve(null);
        };
      } catch (err) {
        console.warn('Eccezione durante open IndexedDB, uso fallback LocalStorage:', err);
        this.useFallback = true;
        resolve(null);
      }
    });
  }

  // --- METODI FALLBACK LOCALSTORAGE ---
  _getFallbackNotes() {
    try {
      const data = localStorage.getItem(this.fallbackKey);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      console.warn('Errore lettura fallback LocalStorage:', e);
      return [];
    }
  }

  _saveFallbackNotes(notes) {
    try {
      localStorage.setItem(this.fallbackKey, JSON.stringify(notes || []));
    } catch (e) {
      console.warn('Errore salvataggio fallback LocalStorage:', e);
    }
  }

  async getAll() {
    if (!this.db && !this.useFallback) await this.init();

    if (this.useFallback || !this.db) {
      return this._getFallbackNotes();
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.getAll();
        request.onsuccess = () => {
          resolve(request.result || []);
        };
        request.onerror = () => {
          console.warn('Errore getAll IndexedDB, fallback su LocalStorage:', request.error);
          resolve(this._getFallbackNotes());
        };
      } catch (err) {
        console.warn('Eccezione transazione getAll IndexedDB:', err);
        resolve(this._getFallbackNotes());
      }
    });
  }

  async get(id) {
    if (!this.db && !this.useFallback) await this.init();

    if (this.useFallback || !this.db) {
      const notes = this._getFallbackNotes();
      return notes.find(n => String(n.id) === String(id));
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get(id);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => {
          const notes = this._getFallbackNotes();
          resolve(notes.find(n => String(n.id) === String(id)));
        };
      } catch (err) {
        const notes = this._getFallbackNotes();
        resolve(notes.find(n => String(n.id) === String(id)));
      }
    });
  }

  async put(note) {
    if (!note || !note.id) return null;
    if (!this.db && !this.useFallback) await this.init();

    if (this.useFallback || !this.db) {
      const fallbackNotes = this._getFallbackNotes().filter(n => String(n.id) !== String(note.id));
      fallbackNotes.push(note);
      this._saveFallbackNotes(fallbackNotes);
      return note.id;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.put(note);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => {
          console.warn('Avviso put IndexedDB:', request.error);
          resolve(note.id);
        };
      } catch (err) {
        console.warn('Eccezione put IndexedDB:', err);
        resolve(note.id);
      }
    });
  }

  async putBatch(notes) {
    if (!Array.isArray(notes) || notes.length === 0) return 0;
    if (!this.db && !this.useFallback) await this.init();

    if (this.useFallback || !this.db) {
      const idMap = new Map();
      for (const n of this._getFallbackNotes()) {
        if (n && n.id) idMap.set(String(n.id), n);
      }
      for (const n of notes) {
        if (n && n.id) idMap.set(String(n.id), n);
      }
      this._saveFallbackNotes(Array.from(idMap.values()));
      return notes.length;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        for (const note of notes) {
          if (note && note.id) {
            store.put(note);
          }
        }
        transaction.oncomplete = () => resolve(notes.length);
        transaction.onerror = () => {
          console.warn('Avviso transazione putBatch IndexedDB:', transaction.error);
          resolve(notes.length);
        };
        transaction.onabort = () => resolve(notes.length);
      } catch (err) {
        console.warn('Eccezione transazione putBatch IndexedDB:', err);
        resolve(notes.length);
      }
    });
  }

  async delete(id) {
    if (!this.db && !this.useFallback) await this.init();

    if (this.useFallback || !this.db) {
      const fallbackNotes = this._getFallbackNotes().filter(n => String(n.id) !== String(id));
      this._saveFallbackNotes(fallbackNotes);
      return true;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.delete(id);
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(true);
      } catch (err) {
        resolve(true);
      }
    });
  }

  async clear() {
    if (this.useFallback || !this.db) {
      this._saveFallbackNotes([]);
      return true;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.clear();
        request.onsuccess = () => resolve(true);
        request.onerror = () => resolve(true);
      } catch (err) {
        resolve(true);
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
    this.currentFilter = 'all'; // 'all', 'photos', 'folder:XYZ', 'day:YYYY-MM-DD'
    this.searchQuery = '';
    this.isAiSearchActive = false;
    this.currentSort = 'date-desc';
    this.notesLimit = 30;
    this._lockListenerAttached = false;
    
    // Editor State
    this.editingNoteId = null;
    this.editorPhotos = []; // array of base64 strings
    this.editorAudio = null; // base64 audio string

    // Voice Recording & Long Press State (~2 Secondi)
    this.longPressTimer = null;
    this.longPressInterval = null;
    this.longPressElapsed = 0;
    this.isLongPressTriggered = false;
    this.isRecording = false;
    this.mediaRecorder = null;
    this.audioChunks = [];
    this.recordedAudioBlobs = []; // Array per concatenazione registrazioni multiple
    this.accumulatedDurationSec = 0;
    this.recordedAudioBlob = null;
    this.recordedAudioBase64 = null;
    this.recordingStartTime = null;
    this.recordingTimerInterval = null;

    // Calendar State
    this.calendarDate = new Date();
    this.selectedCalendarDay = null;

    // Toast Timer
    this.toastTimer = null;

    // PIN Protection State per singole note
    this.pendingUnlockNoteId = null;
    this.pendingUnlockAction = null; // 'open_editor', 'toggle_lock', 'export_pdf'

    // Image Viewer Carousel & Rotation State
    this.viewerPhotos = [];
    this.viewerCurrentIndex = 0;
    this.viewerRotation = 0;
    this.viewerTouchStartX = 0;
    this.viewerTouchStartY = 0;

    // Editor Photos Accordion State (> 4 foto)
    this.editorPhotosExpanded = false;
  }

  async init() {
    // 1. Inizializzazione archivio locale (IndexedDB con fallback automatico su LocalStorage)
    try {
      await this.db.init();
    } catch (dbErr) {
      console.warn('Avviso inizializzazione storage locale:', dbErr);
    }

    // 2. Inizializzazione Tema e Versione Badge
    try {
      this.initTheme();
      const versionEl = document.getElementById('app-version-badge');
      if (versionEl) versionEl.textContent = APP_VERSION;
    } catch (uiErr) {
      console.warn('Avviso inizializzazione interfaccia base:', uiErr);
    }

    // 3. Caricamento note e Rendering iniziale
    try {
      await this.loadNotes();
      this.initEventListeners();
      this.render();
      this.updateStorageStats();
    } catch (renderErr) {
      console.error('Avviso rendering iniziale note:', renderErr);
    }

    // 4. Inizializzazione sincronizzazione Firebase Cloud (Firestore) in modo isolato
    try {
      this.setCloudStatus('syncing', 'Connessione...');
      const fbOnline = await this.firebase.init();

      if (fbOnline) {
        // Sottoscrizione alle modifiche in tempo reale da Firestore con unione intelligente
        this.firebase.subscribeNotes(
          async (cloudNotes) => {
            try {
              if (cloudNotes && cloudNotes.length > 0) {
                await this.mergeCloudNotes(cloudNotes);
              } else if (this.notes.length > 0) {
                this.firebase.saveBatch(this.notes).catch(e => console.warn('Sync initial batch warning:', e));
              }
            } catch (mergeErr) {
              console.warn('Avviso merge cloud notes:', mergeErr);
            } finally {
              this.setCloudStatus('online', 'Sincronizzato');
              this.render();
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
    } catch (fbErr) {
      console.warn('Firebase non attivo o offline:', fbErr);
      this.setCloudStatus('offline', 'Offline (Locale)');
    }

    // 5. Inizializzazione Schermata di Blocco PIN (con scadenza 3 ore)
    try {
      this.initLockScreen();
    } catch (lockErr) {
      console.warn('Avviso lock screen:', lockErr);
    }

    // 6. Rendering icone Lucide
    if (window.lucide) {
      try { lucide.createIcons(); } catch (_) {}
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

  // --- ORDINAMENTO & CARICAMENTO DATI ---
  sortNotes() {
    this.notes.sort((a, b) => {
      const timeA = a && a.date ? (new Date(a.date).getTime() || 0) : 0;
      const timeB = b && b.date ? (new Date(b.date).getTime() || 0) : 0;
      return timeB - timeA;
    });
  }

  async loadNotes() {
    try {
      const raw = await this.db.getAll();
      this.notes = (raw || []).map(n => this.sanitizeNote(n)).filter(Boolean);
      this.sortNotes();
    } catch (e) {
      console.error('Errore lettura note:', e);
      this.notes = [];
    }
  }

  sanitizeNote(n) {
    if (!n || typeof n !== 'object') return null;
    
    let title = n.title;
    if (typeof title === 'object' && title !== null) {
      title = title.title || title.name || JSON.stringify(title);
    }
    title = String(title || 'Senza Titolo').trim();

    let content = n.content !== undefined ? n.content : (n.text || '');
    if (typeof content === 'object' && content !== null) {
      content = content.summary || content.content || JSON.stringify(content, null, 2);
    }
    content = String(content || '').trim();

    let weather = typeof n.weather === 'string' ? n.weather : '';
    let location = typeof n.location === 'string' ? n.location : '';
    let folder = typeof n.folder === 'string' ? n.folder : '';

    return {
      id: String(n.id || ('note_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6))),
      title: title || 'Senza Titolo',
      content: content,
      date: n.date ? String(n.date) : new Date().toISOString(),
      weather: weather,
      location: location,
      folder: folder,
      tags: Array.isArray(n.tags) ? n.tags.map(String) : [],
      photos: Array.isArray(n.photos) ? n.photos : [],
      audio: typeof n.audio === 'string' ? n.audio : null,
      locked: Boolean(n.locked),
      pinned: Boolean(n.pinned),
      createdAt: n.createdAt ? String(n.createdAt) : new Date().toISOString(),
      updatedAt: n.updatedAt ? String(n.updatedAt) : new Date().toISOString()
    };
  }

  async mergeCloudNotes(cloudNotes) {
    if (!Array.isArray(cloudNotes) || cloudNotes.length === 0) return;
    
    // Costruisci mappa delle note locali
    const localMap = new Map(this.notes.map(n => [String(n.id), n]));
    let hasChanges = false;

    for (const rawCn of cloudNotes) {
      if (!rawCn || !rawCn.id) continue;
      const cn = this.sanitizeNote(rawCn);
      if (!cn) continue;

      const noteId = String(cn.id);
      const local = localMap.get(noteId);

      if (!local) {
        // Nuova nota proveniente dal cloud
        localMap.set(noteId, cn);
        hasChanges = true;
      } else {
        // Nota esistente: preserva foto e audio locali se il cloud non li contiene per limiti payload
        const localUpdated = new Date(local.updatedAt || local.date || 0).getTime();
        const cloudUpdated = new Date(cn.updatedAt || cn.date || 0).getTime();
        if (cloudUpdated >= localUpdated) {
          const merged = {
            ...cn,
            photos: (cn.photos && cn.photos.length > 0) ? cn.photos : (local.photos || []),
            audio: cn.audio || local.audio || null,
            locked: (cn.locked !== undefined) ? cn.locked : (local.locked || false)
          };
          localMap.set(noteId, this.sanitizeNote(merged));
          hasChanges = true;
        }
      }
    }

    if (hasChanges || this.notes.length !== localMap.size) {
      this.notes = Array.from(localMap.values()).map(n => this.sanitizeNote(n)).filter(Boolean);
      this.sortNotes();
      // Renderizza immediatamente a schermo per la massima reattività
      this.render();
      this.updateStorageStats();
      // Persisti in IndexedDB in background
      this.db.putBatch(this.notes).catch(e => console.warn('DB merge batch warning:', e));
    }
  }

  // --- SUPPORTO PRESSIONE PROLUNGATA (CIRCA 2 SECONDI) & REGISTRAZIONE VOCALE (HOLD-TO-RECORD) ---
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
      let isRecordingTriggered = false;
      let startX = 0;
      let startY = 0;

      const cleanupHold = () => {
        if (pressTimer) { clearTimeout(pressTimer); pressTimer = null; }
        if (animInterval) { clearInterval(animInterval); animInterval = null; }
        if (progressRing) progressRing.classList.add('hidden');
        if (progressCircle) progressCircle.style.strokeDashoffset = '251';
      };

      const startHold = (e) => {
        // Se stiamo già registrando, il click/tap gestirà lo stop manuale
        if (this.isRecording) return;
        
        isLongPressed = false;
        isRecordingTriggered = false;
        startX = e.clientX || (e.touches && e.touches[0]?.clientX) || 0;
        startY = e.clientY || (e.touches && e.touches[0]?.clientY) || 0;

        let elapsed = 0;
        const total = 1500; // 1.5 secondi di pressione continuata
        const step = 25;

        if (progressRing && progressCircle) {
          progressRing.classList.remove('hidden');
          progressCircle.style.strokeDashoffset = '251';
        }

        animInterval = setInterval(() => {
          elapsed += step;
          const pct = Math.min(elapsed / total, 1);
          if (progressCircle) {
            progressCircle.style.strokeDashoffset = (251 - 251 * pct).toString();
          }
        }, step);

        pressTimer = setTimeout(() => {
          isLongPressed = true;
          isRecordingTriggered = true;
          this.isLongPressRecording = true;
          cleanupHold();
          
          // Feedback aptico (vibrazione)
          if (navigator.vibrate) {
            try { navigator.vibrate([80, 40, 80]); } catch (vErr) {}
          }
          
          // Avvia registrazione vocale mentre il tasto è ancora premuto
          this.startVoiceRecording();
        }, total);
      };

      const handleRelease = () => {
        cleanupHold();

        // Se la registrazione era stata avviata dalla pressione prolungata, si interrompe al rilascio del tasto
        if (isRecordingTriggered || this.isRecording) {
          if (this.isRecording && this.isLongPressRecording) {
            this.stopVoiceRecording();
          }
          isRecordingTriggered = false;
          isLongPressed = true;
          setTimeout(() => {
            isLongPressed = false;
          }, 800);
        }
      };

      // Pointer Down / Touch Start
      btn.addEventListener('pointerdown', (e) => {
        try { if (e.pointerId !== undefined) btn.setPointerCapture(e.pointerId); } catch (err) {}
        startHold(e);
      });

      // Pointer Move (tolleranza aumentata a 60px)
      btn.addEventListener('pointermove', (e) => {
        if (!pressTimer) return;
        const curX = e.clientX || 0;
        const curY = e.clientY || 0;
        if (Math.hypot(curX - startX, curY - startY) > 60) {
          cleanupHold();
        }
      });

      // Pointer Up / Cancel / Touch End (Rilascio tasto)
      btn.addEventListener('pointerup', (e) => {
        try { if (e.pointerId !== undefined) btn.releasePointerCapture(e.pointerId); } catch (err) {}
        handleRelease();
      });
      btn.addEventListener('pointercancel', (e) => {
        try { if (e.pointerId !== undefined) btn.releasePointerCapture(e.pointerId); } catch (err) {}
        handleRelease();
      });

      // Click Event (per tocco rapido normale < 1.5 secondi)
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (isLongPressed || isRecordingTriggered || (Date.now() - (this.lastVoiceRecordingEndTime || 0) < 800)) {
          isLongPressed = false;
          isRecordingTriggered = false;
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

    // Rilascio globale a livello di finestra per massima sicurezza
    window.addEventListener('pointerup', () => {
      if (this.isRecording && this.isLongPressRecording) {
        this.stopVoiceRecording();
      }
    });
  }

  // --- EFFETTI SONORI REGISTRAZIONE VOCALE (WEB AUDIO API) ---
  playRecordingSound(type) {
    try {
      const AudioCtxClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtxClass) return;
      const ctx = new AudioCtxClass();
      
      if (type === 'start') {
        // Suono Inizio Registrazione: doppio tono armonico ascendente (520Hz -> 880Hz)
        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.connect(gain);
        gain.connect(ctx.destination);
        
        osc.frequency.setValueAtTime(520, now);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.12);
        
        gain.gain.setValueAtTime(0.2, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.18);
        
        osc.start(now);
        osc.stop(now + 0.18);
      } else if (type === 'stop') {
        // Suono Fine Registrazione: tono discendente di conferma (880Hz -> 440Hz)
        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.connect(gain);
        gain.connect(ctx.destination);
        
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(440, now + 0.14);
        
        gain.gain.setValueAtTime(0.2, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 0.2);
        
        osc.start(now);
        osc.stop(now + 0.2);
      }
    } catch (e) {
      console.warn('Audio feedback warning:', e);
    }
  }

  // --- REGISTRAZIONE VOCALE (MEDIA RECORDER API) ---
  async startVoiceRecording(isResuming = false) {
    // Rimuovi qualsiasi focus da campi di testo per evitare apertura tastiera mobile
    if (document.activeElement) {
      try { document.activeElement.blur(); } catch (e) {}
    }

    if (this.currentView === 'editor') {
      this.closeEditor();
    }

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

      if (!isResuming) {
        this.recordedAudioBlobs = [];
        this.accumulatedDurationSec = 0;
      }

      this.closeVoiceReviewModal();

      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          this.audioChunks.push(e.data);
        }
      };

      this.mediaRecorder.onstop = () => {
        const currentSegmentBlob = new Blob(this.audioChunks, { type: this.mediaRecorder.mimeType || 'audio/webm' });
        this.recordedAudioBlobs.push(currentSegmentBlob);

        const currentSegmentSec = Math.round((Date.now() - this.recordingStartTime) / 1000);
        this.accumulatedDurationSec += currentSegmentSec;

        // Combina tutti i segmenti audio registrati in un unico Blob
        const mergedBlob = new Blob(this.recordedAudioBlobs, { type: this.mediaRecorder.mimeType || 'audio/webm' });
        this.recordedAudioBlob = mergedBlob;
        
        // Ferma le tracce audio del microfono
        stream.getTracks().forEach(track => track.stop());

        // Converte in Base64 per archiviazione e analisi
        const reader = new FileReader();
        reader.onloadend = () => {
          this.recordedAudioBase64 = reader.result;
          this.openVoiceReviewModal(mergedBlob);
        };
        reader.readAsDataURL(mergedBlob);
      };

      this.mediaRecorder.start(250);
      this.isRecording = true;
      this.recordingStartTime = Date.now();

      // Suono acustico di avvio registrazione rimosso come richiesto

      // UI: nasconde il pulsante tondo in basso e mostra il banner centrale
      this.updateRecordingUI(true);

      // Aggiorna istruzione banner a seconda della modalità
      const instEl = document.getElementById('voice-recording-instruction');
      if (instEl) {
        instEl.textContent = isResuming ? 'Tocca per terminare' : 'Tocca o rilascia per terminare';
      }

      // Timer conteggio registrazione live (continua dalla durata precedentemente accumulata)
      const timerEl = document.getElementById('voice-recording-timer');
      const startOffset = this.accumulatedDurationSec;
      const initialMins = String(Math.floor(startOffset / 60)).padStart(2, '0');
      const initialSecs = String(startOffset % 60).padStart(2, '0');
      if (timerEl) timerEl.textContent = `${initialMins}:${initialSecs}`;

      this.recordingTimerInterval = setInterval(() => {
        const elapsedSec = startOffset + Math.floor((Date.now() - this.recordingStartTime) / 1000);
        const mins = String(Math.floor(elapsedSec / 60)).padStart(2, '0');
        const secs = String(elapsedSec % 60).padStart(2, '0');
        if (timerEl) timerEl.textContent = `${mins}:${secs}`;
      }, 250);

      this.showToast(isResuming ? 'Registrazione vocale ripresa...' : 'Registrazione vocale avviata...', 'info');
    } catch (err) {
      console.error('Errore accesso al microfono:', err);
      this.showToast('Permesso microfono non concesso o non disponibile.', 'error');
      this.updateRecordingUI(false);
      this.isRecording = false;
    }
  }

  resumeVoiceRecording() {
    this.isLongPressRecording = false; // Modalità manuale: continua a registrare finché non si preme STOP
    this.closeVoiceReviewModal();
    if (document.activeElement) {
      try { document.activeElement.blur(); } catch (e) {}
    }
    this.startVoiceRecording(true);
  }

  stopVoiceRecording() {
    if (!this.isRecording) return;
    this.isRecording = false;
    this.isLongPressRecording = false;
    this.lastVoiceRecordingEndTime = Date.now();
    
    if (document.activeElement) {
      try { document.activeElement.blur(); } catch (e) {}
    }

    // Suono acustico di fine registrazione
    this.playRecordingSound('stop');

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
    const fabContainer = document.getElementById('fab-container');
    const fabBtn = document.getElementById('main-fab-btn');
    const fabPlus = document.getElementById('fab-icon-plus');
    const fabStop = document.getElementById('fab-icon-stop');
    const desktopBtn = document.getElementById('desktop-add-btn');
    const desktopPlus = document.getElementById('desktop-add-icon-plus');
    const desktopStop = document.getElementById('desktop-add-icon-stop');
    const desktopText = document.getElementById('desktop-add-text');
    const banner = document.getElementById('voice-recording-banner');

    if (isRec) {
      // Quando parte o si riprende la registrazione, fai sparire il tasto tondo in basso
      fabContainer?.classList.add('opacity-0', 'pointer-events-none');
      desktopBtn?.classList.add('opacity-0', 'pointer-events-none');

      fabBtn?.classList.add('recording-pulse');
      fabPlus?.classList.add('hidden');
      fabStop?.classList.remove('hidden');

      desktopPlus?.classList.add('hidden');
      desktopStop?.classList.remove('hidden');
      if (desktopText) desktopText.textContent = 'STOP';

      banner?.classList.remove('hidden');
    } else {
      // Ripristina la visibilità dei tasti
      fabContainer?.classList.remove('opacity-0', 'pointer-events-none');
      desktopBtn?.classList.remove('opacity-0', 'pointer-events-none');

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

  // --- MODALE REVISIONE VOCALE (CESTINO, REC PER CONTINUARE, SALVA CON IA) ---
  closeVoiceReviewModal() {
    const modal = document.getElementById('voice-review-modal');
    const audioEl = document.getElementById('voice-review-audio');
    if (audioEl) {
      audioEl.pause();
    }
    modal?.classList.add('hidden');
  }

  openVoiceReviewModal(audioBlob) {
    const modal = document.getElementById('voice-review-modal');
    const audioEl = document.getElementById('voice-review-audio');
    const durationEl = document.getElementById('voice-review-duration');
    const loadingEl = document.getElementById('voice-ai-loading');
    const saveBtn = document.getElementById('voice-review-save-btn');

    if (loadingEl) loadingEl.classList.add('hidden');
    if (saveBtn) saveBtn.disabled = false;

    if (audioEl) {
      audioEl.src = URL.createObjectURL(audioBlob);
    }

    if (durationEl) {
      const sec = Math.max(1, this.accumulatedDurationSec || 1);
      const mins = String(Math.floor(sec / 60)).padStart(2, '0');
      const secs = String(sec % 60).padStart(2, '0');
      durationEl.textContent = `Durata: ${mins}:${secs}`;
    }

    modal?.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
  }

  cancelVoiceRecording() {
    this.closeVoiceReviewModal();
    const audioEl = document.getElementById('voice-review-audio');
    if (audioEl) {
      audioEl.pause();
      audioEl.src = '';
    }
    this.recordedAudioBlobs = [];
    this.accumulatedDurationSec = 0;
    this.recordedAudioBlob = null;
    this.recordedAudioBase64 = null;
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

REGOLE DI FORMATTAZIONE OBBLIGATORIE:
- NON usare MAI caratteri di formattazione markdown come asterischi ("*", "**", "***") né cancelletti ("#", "##", "###") né trattini bassi ("_").
- Per gli elenchi puntati usa ESCLUSIVAMENTE il simbolo pallino "• " oppure numeri "1.", "2.".
- Per evidenziare concetti o titoli di sezione usa parole in MAIUSCOLO oppure vai a capo con una riga vuota, SENZA mai usare asterischi o cancelletti.

Rispondi ESCLUSIVAMENTE con un JSON valido con questa esatta struttura:
{
  "title": "Titolo della nota",
  "summary": "Riassunto e testo completo della nota"
}`;

      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}`;

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
          
          // Tracciamento Token consumati
          const tokensUsed = result.usageMetadata?.totalTokenCount || ((result.usageMetadata?.promptTokenCount || 0) + (result.usageMetadata?.candidatesTokenCount || 0)) || Math.round(base64Data.length / 3);
          this.addAiTokenUsage(tokensUsed);

          if (candidateText) {
            try {
              const parsed = JSON.parse(candidateText);
              if (parsed.title) {
                aiTitle = typeof parsed.title === 'string' ? parsed.title : (parsed.title.title || JSON.stringify(parsed.title));
              }
              if (parsed.summary || parsed.content || parsed.text) {
                const s = parsed.summary || parsed.content || parsed.text;
                aiSummary = typeof s === 'string' ? s : JSON.stringify(s, null, 2);
              } else {
                aiSummary = typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
              }
            } catch (e) {
              aiSummary = String(candidateText);
            }
          }
        } else {
          console.warn('Risposta non OK da Gemini 3.6, tentativo con gemini-3.5-flash:', response.status);
          const fallbackEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`;
          const fbRes = await fetch(fallbackEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
          });
          if (fbRes.ok) {
            const fbResult = await fbRes.json();
            const fbText = fbResult.candidates?.[0]?.content?.parts?.[0]?.text || '';
            
            const fbTokensUsed = fbResult.usageMetadata?.totalTokenCount || ((fbResult.usageMetadata?.promptTokenCount || 0) + (fbResult.usageMetadata?.candidatesTokenCount || 0)) || Math.round(base64Data.length / 3);
            this.addAiTokenUsage(fbTokensUsed);

            if (fbText) {
              try {
                const parsed = JSON.parse(fbText);
                if (parsed.title) {
                  aiTitle = typeof parsed.title === 'string' ? parsed.title : (parsed.title.title || JSON.stringify(parsed.title));
                }
                if (parsed.summary || parsed.content || parsed.text) {
                  const s = parsed.summary || parsed.content || parsed.text;
                  aiSummary = typeof s === 'string' ? s : JSON.stringify(s, null, 2);
                } else {
                  aiSummary = typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
                }
              } catch (e) {
                aiSummary = String(fbText);
              }
            }
          }
        }
      } catch (geminiErr) {
        console.error('Errore chiamata Gemini API:', geminiErr);
      }

      // Pulisce rigorosamente il testo da qualsiasi asterisco o cancelletto
      aiTitle = cleanAiFormatting(aiTitle || 'Nota Vocale');
      aiSummary = cleanAiFormatting(aiSummary || 'Registrazione vocale allegata alla nota.');

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
        audio: typeof this.recordedAudioBase64 === 'string' ? this.recordedAudioBase64 : null,
        date: new Date().toISOString(),
        weather: String(autoWeather || ''),
        location: String(autoLocation || ''),
        folder: 'Vocali',
        tags: ['audio', 'ia'],
        photos: [],
        pinned: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      this.setCloudStatus('syncing', 'Salvataggio...');
      
      // Salva prima in IndexedDB
      await this.db.put(newNote);
      
      // Aggiorna array in memoria
      this.notes.unshift(newNote);
      this.sortNotes();

      // Renderizza e aggiorna viste
      this.render();
      this.updateStorageStats();

      // Chiudi modale di revisione audio e pulisci buffer
      this.closeVoiceReviewModal();
      this.recordedAudioBlobs = [];
      this.accumulatedDurationSec = 0;
      this.recordedAudioBlob = null;
      this.recordedAudioBase64 = null;
      this.showToast('Nota vocale creata con successo!', 'success');

      // Apre direttamente la nuova nota nell'editor con titolo e testo compilati da Gemini
      this.openEditor(newNote.id);

      // Sincronizza Firebase in background
      this.firebase.saveNote(newNote)
        .then(() => this.setCloudStatus('online', 'Sincronizzato'))
        .catch(e => {
          console.warn('Sync Firebase note error:', e);
          this.setCloudStatus('offline', 'Offline (Salvato in locale)');
        });
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

    if (viewName === 'notes') {
      this.renderNotesList();
    } else if (viewName === 'calendar') {
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
  // --- FILTRI & RICERCA NOTE ---
  toggleAiSearchMode() {
    this.isAiSearchActive = !this.isAiSearchActive;
    const aiBtn = document.getElementById('chip-filter-ai');
    const searchInput = document.getElementById('search-input');

    if (this.isAiSearchActive) {
      if (aiBtn) {
        aiBtn.className = 'chip-filter px-3 py-1.5 rounded-lg font-bold transition-all bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md shadow-purple-500/30 border border-transparent flex items-center gap-1.5 active:scale-95';
      }
      if (searchInput) {
        searchInput.placeholder = 'Fai una domanda all\'AI sulle tue note e premi Invio...';
        searchInput.focus();
        if (searchInput.value.trim().length > 0) {
          this.performAiSearch(searchInput.value.trim());
        }
      }
    } else {
      if (aiBtn) {
        aiBtn.className = 'chip-filter px-3 py-1.5 rounded-lg font-bold transition-all bg-purple-50 dark:bg-purple-950/50 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/80 hover:bg-purple-100 dark:hover:bg-purple-900/60 flex items-center gap-1.5 shadow-sm';
      }
      if (searchInput) {
        searchInput.placeholder = 'Cerca per titolo, testo, luogo, meteo...';
      }
      this.renderNotesList();
    }
  }

  async performAiSearch(query = null) {
    const searchInput = document.getElementById('search-input');
    const q = (query || searchInput?.value || '').trim();

    if (!q) {
      this.showToast('Digita una domanda o ricerca per l\'AI...', 'info');
      searchInput?.focus();
      return;
    }

    const modal = document.getElementById('ai-search-modal');
    const queryEl = document.getElementById('ai-search-modal-query');
    const loadingEl = document.getElementById('ai-search-loading');
    const resultContainer = document.getElementById('ai-search-result-container');
    const resultTextEl = document.getElementById('ai-search-result-text');
    const notesCountEl = document.getElementById('ai-search-notes-count');

    if (queryEl) queryEl.textContent = `Domanda: "${q}"`;
    if (notesCountEl) notesCountEl.textContent = this.notes.length;
    if (loadingEl) loadingEl.classList.remove('hidden');
    if (resultContainer) resultContainer.classList.add('hidden');
    if (resultTextEl) resultTextEl.textContent = '';

    modal?.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();

    try {
      // 1. Prepara il contesto sintetico di tutte le note dell'utente
      const notesContext = this.notes.map((n, i) => {
        const titleStr = n.title ? `Titolo: ${n.title}` : 'Senza Titolo';
        const dateStr = n.date ? `Data: ${n.date}` : '';
        const locStr = n.location ? `Luogo: ${n.location}` : '';
        const weatherStr = n.weather ? `Meteo: ${n.weather}` : '';
        const folderStr = n.folder ? `Cartella: ${n.folder}` : '';
        const meta = [titleStr, dateStr, locStr, weatherStr, folderStr].filter(Boolean).join(' | ');
        return `[Nota #${i + 1}] ${meta}\nTesto:\n${n.content || '(nessun testo)'}`;
      }).join('\n\n---\n\n');

      // 2. Prompt per Gemini AI
      const promptText = `Sei l'assistente AI personale intelligente integrato nell'app di note MassiNote.
L'utente ti sta ponendo una domanda o una richiesta di ricerca sul suo archivio note personale.

DOMANDA DELL'UTENTE:
"${q}"

ARCHIVIO COMPLETO DELLE NOTE DELL'UTENTE (${this.notes.length} note totali):
${notesContext}

ISTRUZIONI PER LA RISPOSTA:
1. Rispondi sempre in lingua italiana in modo chiaro, ordinato, completo e cordiale.
2. Basa la tua risposta ESCLUSIVAMENTE sui contenuti, date, luoghi e informazioni presenti nelle note dell'utente fornite sopra.
3. Se pertinente, cita date, nomi, luoghi o dettagli esatti citati nelle note.
4. Se nelle note non c'è alcuna informazione pertinente per rispondere alla domanda, dillo con gentilezza e chiarezza spiegando che non sono state trovate note relative.
5. REGOLE DI FORMATTAZIONE OBBLIGATORIE: NON usare MAI caratteri di sintassi markdown come asterischi ("*", "**", "***") né cancelletti ("#", "##", "###"). Usa elenchi puntati con "• " o numeri, e maiuscole per i titoli di sezione.`;

      const apiKey = getDecryptedGeminiKey();
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}`;

      const requestBody = {
        contents: [
          {
            parts: [{ text: promptText }]
          }
        ]
      };

      let aiResponseText = '';
      let tokensUsed = 0;

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody)
      });

      if (response.ok) {
        const result = await response.json();
        aiResponseText = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
        tokensUsed = result.usageMetadata?.totalTokenCount || ((result.usageMetadata?.promptTokenCount || 0) + (result.usageMetadata?.candidatesTokenCount || 0)) || Math.round(promptText.length / 4);
      } else {
        console.warn('Fallback a gemini-3.5-flash per ricerca AI:', response.status);
        const fbEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=${apiKey}`;
        const fbRes = await fetch(fbEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody)
        });
        if (fbRes.ok) {
          const fbResult = await fbRes.json();
          aiResponseText = fbResult.candidates?.[0]?.content?.parts?.[0]?.text || '';
          tokensUsed = fbResult.usageMetadata?.totalTokenCount || ((fbResult.usageMetadata?.promptTokenCount || 0) + (fbResult.usageMetadata?.candidatesTokenCount || 0)) || Math.round(promptText.length / 4);
        }
      }

      if (tokensUsed > 0) {
        this.addAiTokenUsage(tokensUsed);
      }

      if (!aiResponseText) {
        aiResponseText = "Non è stato possibile ottenere una risposta dall'AI. Verifica la connessione e riprova.";
      } else {
        aiResponseText = cleanAiFormatting(aiResponseText);
      }

      if (resultTextEl) resultTextEl.textContent = aiResponseText;
      if (loadingEl) loadingEl.classList.add('hidden');
      if (resultContainer) resultContainer.classList.remove('hidden');

    } catch (err) {
      console.error('Errore ricerca AI:', err);
      if (loadingEl) loadingEl.classList.add('hidden');
      if (resultContainer) resultContainer.classList.remove('hidden');
      if (resultTextEl) resultTextEl.textContent = `Si è verificato un errore durante la ricerca AI: ${err.message || err}`;
    }
  }

  closeAiSearchModal() {
    const modal = document.getElementById('ai-search-modal');
    modal?.classList.add('hidden');

    // Quando il popup viene chiuso, il tasto AI torna come di default disattivato
    this.isAiSearchActive = false;
    const aiBtn = document.getElementById('chip-filter-ai');
    if (aiBtn) {
      aiBtn.className = 'chip-filter px-3 py-1.5 rounded-lg font-bold transition-all bg-purple-50 dark:bg-purple-950/50 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/80 hover:bg-purple-100 dark:hover:bg-purple-900/60 flex items-center gap-1.5 shadow-sm';
    }
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.placeholder = 'Cerca per titolo, testo, luogo, meteo...';
    }
    this.renderNotesList();
  }

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
    ['chip-filter-all', 'chip-filter-photos'].forEach(id => {
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

    // Ordinamento di default: sempre per data più recente in alto (con gestione sicura timestamp)
    result.sort((a, b) => {
      const timeA = a && a.date ? (new Date(a.date).getTime() || 0) : 0;
      const timeB = b && b.date ? (new Date(b.date).getTime() || 0) : 0;
      return timeB - timeA;
    });

    // Filtro Ricerca
    if (this.searchQuery) {
      result = result.filter(n => {
        if (!n) return false;
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
      result = result.filter(n => n && Array.isArray(n.photos) && n.photos.length > 0);
    } else if (this.currentFilter === 'recent') {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      result = result.filter(n => {
        if (!n || !n.date) return false;
        const d = new Date(n.date);
        return !isNaN(d.getTime()) && d >= thirtyDaysAgo;
      });
    } else if (this.currentFilter.startsWith('day:')) {
      const targetDayStr = this.currentFilter.replace('day:', '');
      result = result.filter(n => {
        if (!n || !n.date) return false;
        const d = new Date(n.date);
        if (isNaN(d.getTime())) return false;
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${y}-${m}-${day}` === targetDayStr;
      });
    } else if (this.currentFilter.startsWith('folder:')) {
      const targetFolder = this.currentFilter.replace('folder:', '').toLowerCase();
      result = result.filter(n => n && (n.folder || '').toLowerCase() === targetFolder);
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
    const withPhotos = this.notes.filter(n => n && Array.isArray(n.photos) && n.photos.length > 0).length;

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
      if (!note) return '';
      const safeId = String(note.id || '').replace(/'/g, "\\'");
      let dateObj = parseDateSafe(note.date);
      const formattedDate = formatItalianDate(dateObj);
      const hasPhotos = Array.isArray(note.photos) && note.photos.length > 0;
      const photosCount = hasPhotos ? note.photos.length : 0;

      // Snippet del contenuto e stato di blocco
      const isLocked = !!note.locked;
      const previewText = (note.content || '').replace(/\n+/g, ' ').trim() || 'Nessun testo';

      // Badge Protezione Password
      const lockBadgeHtml = isLocked
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-900/60 shadow-sm" title="Nota protetta da password">
             <i data-lucide="lock" class="w-3 h-3 text-amber-600 dark:text-amber-400"></i>
             <span>Protetta</span>
           </span>`
        : '';

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
             <span>${escapeHtml(note.weather)}</span>
           </span>`
        : '';

      // Badge Luogo
      const locationBadgeHtml = note.location
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-900/50 max-w-[150px] truncate" title="${escapeHtml(note.location)}">
             <i data-lucide="map-pin" class="w-3 h-3 text-emerald-500 shrink-0"></i>
             <span class="truncate">${escapeHtml(note.location)}</span>
           </span>`
        : '';

      // Badge Cartella
      const folderBadgeHtml = note.folder
        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900/50">
             <i data-lucide="folder" class="w-3 h-3 text-indigo-500"></i>
             <span>${escapeHtml(note.folder)}</span>
           </span>`
        : '';

      // Anteprima contenuto: mascherata se la nota è protetta da password
      const contentPreviewHtml = isLocked
        ? `<div class="mt-1.5 py-1.5 px-2.5 rounded-xl bg-amber-50/80 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-200/60 dark:border-amber-900/50 flex items-center gap-2 text-xs font-semibold select-none">
             <i data-lucide="shield-check" class="w-4 h-4 text-amber-500 shrink-0"></i>
             <span>Contenuto protetto da password</span>
           </div>`
        : `<p class="text-xs text-slate-600 dark:text-slate-400 mt-1 line-clamp-3 leading-relaxed">${escapeHtml(previewText)}</p>`;

      // Prima miniatura foto (se presente e non bloccata)
      const thumbnailHtml = (hasPhotos && note.photos[0])
        ? (isLocked 
            ? `<div class="w-16 h-16 sm:w-20 sm:h-20 rounded-xl overflow-hidden bg-amber-50/80 dark:bg-slate-800 shrink-0 border border-amber-200 dark:border-slate-700 flex flex-col items-center justify-center text-amber-600 dark:text-amber-400 shadow-inner">
                 <i data-lucide="lock" class="w-5 h-5"></i>
                 <span class="text-[9px] font-bold mt-0.5">${photosCount} foto</span>
               </div>`
            : `<div class="w-16 h-16 sm:w-20 sm:h-20 rounded-xl overflow-hidden bg-slate-100 dark:bg-slate-800 shrink-0 border border-slate-200 dark:border-slate-700 cursor-pointer shadow-inner relative group" onclick="event.stopPropagation(); app.openImageViewerForNote('${safeId}', 0)">
                 <img src="${note.photos[0]}" alt="Foto Nota" class="w-full h-full object-cover group-hover:scale-105 transition-transform">
                 ${photosCount > 1 ? `<span class="absolute bottom-1 right-1 bg-black/70 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-md backdrop-blur-xs">+${photosCount - 1}</span>` : ''}
               </div>`
          )
        : '';

      return `
        <article 
          onclick="app.openNoteOrPromptPin('${safeId}')"
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
                ${lockBadgeHtml}
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
                ${contentPreviewHtml}
              </div>
              ${thumbnailHtml}
            </div>
          </div>

          <!-- Footer Card: Metadati e Azioni Veloci -->
          <div class="pt-2 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between gap-2 text-xs">
            <div class="flex items-center gap-1.5 flex-wrap max-w-[55%] sm:max-w-[65%]">
              ${locationBadgeHtml}
              ${folderBadgeHtml}
            </div>

            <div class="flex items-center gap-1 shrink-0">
              <!-- 1. Tasto Condividi -->
              <button 
                onclick="event.stopPropagation(); app.shareNote('${safeId}')" 
                class="p-1.5 rounded-lg text-slate-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-slate-800 transition-colors cursor-pointer" 
                title="Copia / Condividi testo"
              >
                <i data-lucide="share-2" class="w-3.5 h-3.5"></i>
              </button>

              <!-- 2. Tasto PDF (Esporta nota e foto in PDF) -->
              <button 
                onclick="event.stopPropagation(); app.exportNoteToPdf('${safeId}')" 
                class="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-slate-800 transition-colors cursor-pointer" 
                title="Esporta nota in PDF"
              >
                <i data-lucide="file-text" class="w-3.5 h-3.5 text-red-500"></i>
              </button>

              <!-- 3. Tasto Chiave/Lucchetto (Protezione Password 1804) -->
              <button 
                onclick="event.stopPropagation(); app.toggleNoteLock('${safeId}')" 
                class="p-1.5 rounded-lg ${isLocked ? 'text-amber-500 bg-amber-50 dark:bg-amber-950/40' : 'text-slate-400'} hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-slate-800 transition-colors cursor-pointer" 
                title="${isLocked ? 'Rimuovi protezione password' : 'Proteggi nota con password'}"
              >
                <i data-lucide="${isLocked ? 'lock' : 'key'}" class="w-3.5 h-3.5"></i>
              </button>

              <!-- 4. Tasto Elimina -->
              <button 
                onclick="event.stopPropagation(); app.confirmDeleteNote('${safeId}')" 
                class="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-slate-800 transition-colors cursor-pointer" 
                title="Elimina nota"
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

  // --- ESPORTAZIONE PDF SINGOLA NOTA & FOTO ---
  exportNoteToPdf(noteId) {
    const note = this.notes.find(n => n && String(n.id) === String(noteId));
    if (!note) {
      this.showToast('Nota non trovata', 'error');
      return;
    }

    if (note.locked) {
      this.pendingUnlockNoteId = noteId;
      this.pendingUnlockAction = 'export_pdf';
      this.openNotePinModal();
      return;
    }

    this._generateAndPrintPdf(note);
  }

  _generateAndPrintPdf(note) {
    let dateObj = parseDateSafe(note.date);
    const dateFormatted = formatFullItalianDate(dateObj) || formatItalianDate(dateObj);
    const title = escapeHtml(note.title || 'Senza Titolo');
    const folder = note.folder ? `<span style="background:#e0e7ff;color:#3730a3;padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700;margin-right:8px;">📁 ${escapeHtml(note.folder)}</span>` : '';
    const location = note.location ? `<span style="background:#dcfce7;color:#166534;padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700;margin-right:8px;">📍 ${escapeHtml(note.location)}</span>` : '';
    const weather = note.weather ? `<span style="background:#fef3c7;color:#92400e;padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700;margin-right:8px;">☀️ ${escapeHtml(note.weather)}</span>` : '';

    let photosHtml = '';
    if (Array.isArray(note.photos) && note.photos.length > 0) {
      photosHtml = `
        <div style="margin-top:28px;border-top:2px dashed #cbd5e1;padding-top:20px;page-break-inside:avoid;">
          <h4 style="font-size:14px;font-weight:800;color:#334155;margin-bottom:14px;text-transform:uppercase;letter-spacing:0.5px;">Fotografie Allegate (${note.photos.length})</h4>
          <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(200px, 1fr));gap:14px;">
            ${note.photos.map((p, idx) => `<div style="border-radius:12px;overflow:hidden;border:1px solid #cbd5e1;background:#f8fafc;"><img src="${p}" style="width:100%;height:180px;object-fit:cover;display:block;" alt="Foto ${idx+1}"></div>`).join('')}
          </div>
        </div>
      `;
    }

    const printFrame = document.createElement('iframe');
    printFrame.style.position = 'fixed';
    printFrame.style.right = '0';
    printFrame.style.bottom = '0';
    printFrame.style.width = '0';
    printFrame.style.height = '0';
    printFrame.style.border = '0';
    document.body.appendChild(printFrame);

    const doc = printFrame.contentWindow.document;
    doc.open();
    doc.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>${title} - MassiNote</title>
          <style>
            @page { size: A4; margin: 18mm 15mm; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; line-height: 1.65; margin: 0; padding: 24px; }
            .header { border-bottom: 2.5px solid #2563eb; padding-bottom: 14px; margin-bottom: 22px; }
            .app-title { font-size: 11px; font-weight: 800; color: #2563eb; text-transform: uppercase; letter-spacing: 1.5px; }
            .note-title { font-size: 24px; font-weight: 800; color: #0f172a; margin: 6px 0 10px 0; line-height: 1.25; }
            .meta { font-size: 13px; color: #64748b; font-weight: 600; margin-bottom: 10px; }
            .badges { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
            .content { font-size: 14.5px; color: #334155; white-space: pre-wrap; word-break: break-word; background: #f8fafc; padding: 18px; border-radius: 14px; border: 1px solid #e2e8f0; line-height: 1.7; }
            @media print {
              body { padding: 0; }
              .content { background: transparent; border: none; padding: 0; }
            }
          </style>
        </head>
        <body>
          <div class="header">
            <div class="app-title">MassiNote • Documento di Nota</div>
            <h1 class="note-title">${title}</h1>
            <div class="meta">📅 ${dateFormatted}</div>
            <div class="badges">
              ${folder} ${location} ${weather}
            </div>
          </div>
          <div class="content">${escapeHtml(note.content || 'Nessun testo')}</div>
          ${photosHtml}
        </body>
      </html>
    `);
    doc.close();

    setTimeout(() => {
      printFrame.contentWindow.focus();
      printFrame.contentWindow.print();
      setTimeout(() => {
        if (printFrame.parentNode) {
          document.body.removeChild(printFrame);
        }
      }, 2000);
    }, 500);

    this.showToast('Esportazione PDF avviata...', 'info');
  }

  // --- GESTIONE BLOCCO PASSWORD (PIN 1804) PER SINGOLE NOTE ---
  toggleNoteLock(noteId) {
    const note = this.notes.find(n => n && String(n.id) === String(noteId));
    if (!note) return;

    if (note.locked) {
      // Se è già protetta, richiedi il PIN prima di rimuovere la protezione
      this.pendingUnlockNoteId = noteId;
      this.pendingUnlockAction = 'toggle_lock';
      this.openNotePinModal();
    } else {
      // Attiva protezione
      note.locked = true;
      note.updatedAt = new Date().toISOString();
      this.db.put(note);
      this.firebase.saveNote(note).catch(() => {});
      this.render();
      this.renderStats();
      this.showToast('Nota protetta con password!', 'success');
    }
  }

  openNoteOrPromptPin(noteId) {
    const note = this.notes.find(n => n && String(n.id) === String(noteId));
    if (!note) return;

    if (note.locked) {
      this.pendingUnlockNoteId = noteId;
      this.pendingUnlockAction = 'open_editor';
      this.openNotePinModal();
    } else {
      this.openEditor(noteId);
    }
  }

  openNotePinModal() {
    const modal = document.getElementById('note-pin-modal');
    const input = document.getElementById('note-pin-input');
    const errorEl = document.getElementById('note-pin-error');
    if (errorEl) errorEl.classList.add('hidden');
    if (input) input.value = '';
    modal?.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
    setTimeout(() => input?.focus(), 250);
  }

  closeNotePinModal() {
    const modal = document.getElementById('note-pin-modal');
    const input = document.getElementById('note-pin-input');
    if (input) input.value = '';
    this.pendingUnlockNoteId = null;
    this.pendingUnlockAction = null;
    modal?.classList.add('hidden');
  }

  async verifyNotePin() {
    const input = document.getElementById('note-pin-input');
    const errorEl = document.getElementById('note-pin-error');
    const cardEl = document.getElementById('note-pin-card');
    if (!input) return;

    const val = input.value.trim();
    if (!val) return;

    const enteredHash = await calculateSha256(val);
    if (enteredHash === _0xSEC_PIN_HASH) {
      const targetId = this.pendingUnlockNoteId;
      const action = this.pendingUnlockAction;
      this.closeNotePinModal();

      if (action === 'toggle_lock') {
        const note = this.notes.find(n => n && String(n.id) === String(targetId));
        if (note) {
          note.locked = false;
          note.updatedAt = new Date().toISOString();
          await this.db.put(note);
          this.firebase.saveNote(note).catch(() => {});
          this.render();
          this.renderStats();
          this.showToast('Protezione rimossa dalla nota', 'info');
        }
      } else if (action === 'export_pdf') {
        const note = this.notes.find(n => n && String(n.id) === String(targetId));
        if (note) this._generateAndPrintPdf(note);
      } else {
        this.openEditor(targetId);
      }
    } else {
      if (errorEl) errorEl.classList.remove('hidden');
      if (cardEl) {
        cardEl.classList.remove('shake');
        void cardEl.offsetWidth;
        cardEl.classList.add('shake');
      }
      if (input) {
        input.value = '';
        input.focus();
      }
    }
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

  toggleStatSection(key) {
    const content = document.getElementById(`stat-content-${key}`);
    const icon = document.getElementById(`stat-icon-${key}`);
    if (!content) return;
    const isHidden = content.classList.toggle('hidden');
    if (icon) {
      icon.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
    }
  }

  // --- STATISTICHE ---
  renderStats() {
    const totalNotes = this.notes.length;
    const protectedNotes = this.notes.filter(n => n && n.locked).length;
    const pctProtected = totalNotes > 0 ? Math.round((protectedNotes / totalNotes) * 100) : 0;

    const audioNotes = this.notes.filter(n => n && (n.audio || (Array.isArray(n.tags) && (n.tags.includes('audio') || n.tags.includes('ia'))))).length;
    const pctAudio = totalNotes > 0 ? Math.round((audioNotes / totalNotes) * 100) : 0;

    const withPhotos = this.notes.filter(n => n && n.photos && n.photos.length > 0).length;
    const pctPhotos = totalNotes > 0 ? Math.round((withPhotos / totalNotes) * 100) : 0;

    // Conteggio parole e raggruppamenti
    let totalWords = 0;
    const locationsMap = {};
    const foldersMap = {};
    const yearsMap = {};
    let tempSum = 0;
    let tempCount = 0;

    for (const n of this.notes) {
      if (!n) continue;
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

    // Aggiorna KPI DOM Principali
    const totalNotesEl = document.getElementById('stat-total-notes');
    if (totalNotesEl) totalNotesEl.textContent = totalNotes;

    const protectedNotesEl = document.getElementById('stat-protected-notes');
    if (protectedNotesEl) protectedNotesEl.textContent = protectedNotes;

    const protectedPctEl = document.getElementById('stat-protected-pct');
    if (protectedPctEl) protectedPctEl.textContent = `${pctProtected}% delle note`;

    const audioNotesEl = document.getElementById('stat-audio-notes');
    if (audioNotesEl) audioNotesEl.textContent = audioNotes;

    const audioPctEl = document.getElementById('stat-audio-pct');
    if (audioPctEl) audioPctEl.textContent = `${pctAudio}% del totale`;

    const photosNotesEl = document.getElementById('stat-photos-notes');
    if (photosNotesEl) photosNotesEl.textContent = withPhotos;

    const photosPctEl = document.getElementById('stat-photos-pct');
    if (photosPctEl) photosPctEl.textContent = `${pctPhotos}% delle note`;

    const totalWordsEl = document.getElementById('stat-total-words');
    if (totalWordsEl) totalWordsEl.textContent = totalWords.toLocaleString('it-IT');

    const avgWordsEl = document.getElementById('stat-avg-words');
    if (avgWordsEl) avgWordsEl.textContent = `Media: ${avgWords} parole/nota`;

    const locationsCountEl = document.getElementById('stat-locations-count');
    if (locationsCountEl) locationsCountEl.textContent = Object.keys(locationsMap).length;

    const avgTempEl = document.getElementById('stat-avg-temp');
    if (avgTempEl) avgTempEl.textContent = tempCount > 0 ? `Temp. media: ${avgTemp}` : 'Nessun dato meteo';

    // Aggiorna Spazio DB e Token AI
    this.updateStorageStats();

    // 1. Ripartizione Anni
    const sortedYears = Object.keys(yearsMap).sort((a, b) => b - a);
    const yearsBadge = document.getElementById('stat-years-count-badge');
    if (yearsBadge) {
      yearsBadge.textContent = `${sortedYears.length} ${sortedYears.length === 1 ? 'Anno' : 'Anni'}`;
    }

    const yearsContainer = document.getElementById('stat-years-breakdown');
    if (yearsContainer) {
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

    // 2. Top Luoghi
    const topLocations = Object.entries(locationsMap).sort((a, b) => b[1] - a[1]);
    const locationsBadge = document.getElementById('stat-locations-count-badge');
    if (locationsBadge) {
      locationsBadge.textContent = `${topLocations.length} ${topLocations.length === 1 ? 'Luogo' : 'Luoghi'}`;
    }

    const locContainer = document.getElementById('stat-locations-list');
    if (locContainer) {
      const displayLocations = topLocations.slice(0, 10);
      if (displayLocations.length === 0) {
        locContainer.innerHTML = `<p class="text-xs text-slate-400 italic">Nessun luogo registrato nelle note.</p>`;
      } else {
        locContainer.innerHTML = displayLocations.map(([loc, cnt]) => `
          <div class="flex justify-between items-center bg-slate-50 dark:bg-slate-800/60 p-2.5 rounded-xl">
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

    // 3. Top Cartelle
    const topFolders = Object.entries(foldersMap).sort((a, b) => b[1] - a[1]);
    const foldersBadge = document.getElementById('stat-folders-count-badge');
    if (foldersBadge) {
      foldersBadge.textContent = `${topFolders.length} ${topFolders.length === 1 ? 'Cartella' : 'Cartelle'}`;
    }

    const folderContainer = document.getElementById('stat-folders-list');
    if (folderContainer) {
      const displayFolders = topFolders.slice(0, 10);
      if (displayFolders.length === 0) {
        folderContainer.innerHTML = `<p class="text-xs text-slate-400 italic">Nessuna cartella o categoria specificata.</p>`;
      } else {
        folderContainer.innerHTML = displayFolders.map(([f, cnt]) => `
          <div class="flex justify-between items-center bg-slate-50 dark:bg-slate-800/60 p-2.5 rounded-xl">
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

    this.editorPhotosExpanded = false;
    this.renderEditorPhotos();
    this.renderEditorAudio();
    this.onEditorContentChange();

    // Passa alla schermata editor a tutto schermo
    this.switchView('editor');
    this.adjustEditorTextareaHeight();

    // Ricalcola l'altezza esatta dopo il rendering della vista ed eventuale focus
    setTimeout(() => {
      this.adjustEditorTextareaHeight();
      if (!noteId) titleInput?.focus();
    }, 80);

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
    const textarea = document.getElementById('editor-content');
    const content = textarea?.value || '';
    const words = content.trim() ? content.trim().split(/\s+/).length : 0;
    const wordCountEl = document.getElementById('editor-word-count');
    if (wordCountEl) {
      wordCountEl.textContent = `${words} ${words === 1 ? 'parola' : 'parole'}`;
    }
    this.adjustEditorTextareaHeight();
  }

  adjustEditorTextareaHeight() {
    const textarea = document.getElementById('editor-content');
    if (!textarea) return;
    // Resetta l'altezza a 0 prima di misurare lo scrollHeight reale
    textarea.style.height = 'auto';
    const newHeight = Math.max(250, textarea.scrollHeight);
    textarea.style.height = `${newHeight}px`;
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
    } else if (type === 'divider') {
      replacement = `\n------------------------------------------------------------------------------------------------\n`;
    } else if (type === 'date' || type === 'time') {
      const now = new Date();
      const day = String(now.getDate()).padStart(2, '0');
      const month = String(now.getMonth() + 1).padStart(2, '0');
      const year = String(now.getFullYear()).slice(-2);
      replacement = `${day}/${month}/${year}`;
    }

    textarea.setRangeText(replacement, start, end, 'end');
    textarea.focus();
    this.onEditorContentChange();
  }

  // --- AVVIO REGISTRAZIONE VOCALE DALL'EDITOR (PARTE DA ZERO CON RIQUADRO CENTRALE) ---
  startVoiceRecordingFromEditor() {
    if (document.activeElement) {
      try { document.activeElement.blur(); } catch (e) {}
    }
    this.isLongPressRecording = false; // Modalità tocco manuale
    this.startVoiceRecording(false);
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
        const base64 = await this.resizeAndEncodeImage(file, 1080, 0.72);
        this.editorPhotos.push(base64);
      } catch (err) {
        console.error('Errore caricamento immagine:', err);
        this.showToast('Errore nel caricamento della foto', 'error');
      }
    }

    this.renderEditorPhotos();
    event.target.value = '';
  }

  resizeAndEncodeImage(file, maxDimension = 1080, quality = 0.72) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          let width = img.width || 1;
          let height = img.height || 1;

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

  toggleEditorPhotosExpand() {
    this.editorPhotosExpanded = !this.editorPhotosExpanded;
    this.renderEditorPhotos();
  }

  renderEditorPhotos() {
    const container = document.getElementById('editor-photos-container');
    const grid = document.getElementById('editor-photos-grid');
    const countEl = document.getElementById('editor-photos-count');
    const expandIcon = document.getElementById('editor-photos-expand-icon');
    const expandBadge = document.getElementById('editor-photos-expand-badge');

    if (this.editorPhotos.length === 0) {
      container?.classList.add('hidden');
      return;
    }

    container?.classList.remove('hidden');
    if (countEl) countEl.textContent = this.editorPhotos.length;

    const totalPhotos = this.editorPhotos.length;
    const hasMoreThan4 = totalPhotos > 4;

    if (hasMoreThan4) {
      expandIcon?.classList.remove('hidden');
      expandBadge?.classList.remove('hidden');

      if (this.editorPhotosExpanded) {
        if (expandIcon) expandIcon.style.transform = 'rotate(180deg)';
        if (expandBadge) expandBadge.textContent = 'Comprimi';
      } else {
        if (expandIcon) expandIcon.style.transform = 'rotate(0deg)';
        if (expandBadge) expandBadge.textContent = `+${totalPhotos - 4} altre (Mostra tutte)`;
      }
    } else {
      expandIcon?.classList.add('hidden');
      expandBadge?.classList.add('hidden');
    }

    if (!grid) return;

    const photosToDisplay = (hasMoreThan4 && !this.editorPhotosExpanded)
      ? this.editorPhotos.slice(0, 4)
      : this.editorPhotos;

    grid.innerHTML = photosToDisplay.map((photoBase64, idx) => `
      <div class="relative group aspect-square rounded-xl overflow-hidden bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm">
        <img src="${photoBase64}" alt="Foto ${idx + 1}" class="w-full h-full object-cover cursor-pointer hover:scale-105 transition-transform" onclick="app.openImageViewerForEditor(${idx})">
        <button 
          type="button" 
          onclick="app.removeEditorPhoto(${idx})" 
          class="absolute top-1.5 right-1.5 p-1 bg-red-600 hover:bg-red-700 text-white rounded-full shadow-md transition-all active:scale-90 cursor-pointer"
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
    if (!id) return;
    const note = this.notes.find(n => n.id === id);
    this.openConfirmModal(
      'Elimina Nota',
      `Sei sicuro di voler eliminare la nota "${note?.title || 'selezionata'}"? L'azione non può essere annullata.`,
      async () => {
        try {
          this.setCloudStatus('syncing', 'Eliminazione...');
          await this.db.delete(id);
          
          const idx = this.notes.findIndex(n => n.id === id);
          if (idx >= 0) this.notes.splice(idx, 1);
          
          this.firebase.deleteNote(id).catch(e => console.warn('Delete Firebase warning:', e));
          this.render();
          this.updateStorageStats();
          this.setCloudStatus('online', 'Sincronizzato');
          this.showToast('Nota eliminata con successo', 'info');
        } catch (e) {
          console.error('Errore eliminazione nota:', e);
          this.showToast('Errore durante l\'eliminazione della nota', 'error');
        }
      }
    );
  }

  deleteCurrentNote() {
    const idToDelete = this.editingNoteId;
    if (!idToDelete) return;
    
    const note = this.notes.find(n => n.id === idToDelete);
    this.openConfirmModal(
      'Elimina Nota',
      `Sei sicuro di voler eliminare la nota "${note?.title || 'selezionata'}"? L'azione non può essere annullata.`,
      async () => {
        try {
          this.setCloudStatus('syncing', 'Eliminazione...');
          this.closeEditor();
          await this.db.delete(idToDelete);
          
          const idx = this.notes.findIndex(n => n.id === idToDelete);
          if (idx >= 0) this.notes.splice(idx, 1);
          
          this.firebase.deleteNote(idToDelete).catch(e => console.warn('Delete Firebase warning:', e));
          this.render();
          this.updateStorageStats();
          this.setCloudStatus('online', 'Sincronizzato');
          this.showToast('Nota eliminata con successo', 'info');
        } catch (e) {
          console.error('Errore eliminazione nota editor:', e);
          this.showToast('Errore durante l\'eliminazione della nota', 'error');
        }
      }
    );
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

  // --- VISUALIZZATORE FOTO FULLSCREEN CON CAROSELLO & SMART ROTATION ---
  openImageViewerForNote(noteId, startIndex = 0) {
    const note = this.notes.find(n => n && String(n.id) === String(noteId));
    if (!note || !Array.isArray(note.photos) || note.photos.length === 0) return;
    
    if (note.locked) {
      this.pendingUnlockNoteId = noteId;
      this.pendingUnlockAction = 'open_editor';
      this.openNotePinModal();
      return;
    }

    this.openImageViewer(note.photos, startIndex);
  }

  openImageViewerForEditor(startIndex = 0) {
    if (!Array.isArray(this.editorPhotos) || this.editorPhotos.length === 0) return;
    this.openImageViewer(this.editorPhotos, startIndex);
  }

  openImageViewer(photos, startIndex = 0) {
    const modal = document.getElementById('image-viewer-modal');
    if (!modal) return;

    if (Array.isArray(photos)) {
      this.viewerPhotos = photos.filter(Boolean);
    } else if (typeof photos === 'string') {
      this.viewerPhotos = [photos];
    } else {
      this.viewerPhotos = [];
    }

    if (this.viewerPhotos.length === 0) return;

    this.viewerCurrentIndex = Math.max(0, Math.min(startIndex, this.viewerPhotos.length - 1));
    this.viewerRotation = 0;

    modal.classList.remove('hidden');
    this.loadCurrentViewerPhoto();
    if (window.lucide) lucide.createIcons();
  }

  loadCurrentViewerPhoto() {
    const img = document.getElementById('image-viewer-img');
    const counterEl = document.getElementById('image-viewer-counter');
    const prevBtn = document.getElementById('image-viewer-prev-btn');
    const nextBtn = document.getElementById('image-viewer-next-btn');

    if (counterEl) {
      counterEl.textContent = `Foto ${this.viewerCurrentIndex + 1} di ${this.viewerPhotos.length}`;
    }

    if (prevBtn && nextBtn) {
      if (this.viewerPhotos.length <= 1) {
        prevBtn.classList.add('hidden');
        nextBtn.classList.add('hidden');
      } else {
        prevBtn.classList.remove('hidden');
        nextBtn.classList.remove('hidden');
      }
    }

    this.renderViewerThumbnails();

    if (img && this.viewerPhotos[this.viewerCurrentIndex]) {
      img.onload = () => {
        this.applySmartAutoRotation();
      };
      img.src = this.viewerPhotos[this.viewerCurrentIndex];
    }
  }

  applySmartAutoRotation() {
    const img = document.getElementById('image-viewer-img');
    if (!img) return;

    const screenW = window.innerWidth;
    const screenH = window.innerHeight;
    const isScreenPortrait = screenH > screenW;

    const imgW = img.naturalWidth || 1;
    const imgH = img.naturalHeight || 1;
    const isImageLandscape = imgW > imgH;

    // Se lo schermo è verticale (smartphone) e la foto è orizzontale (landscape)
    // ruota automaticamente di 90° per sfruttare l'altezza dello schermo a tutto schermo
    if (isScreenPortrait && isImageLandscape) {
      this.viewerRotation = 90;
    } else {
      this.viewerRotation = 0;
    }

    this.updateImageTransform();
  }

  updateImageTransform() {
    const img = document.getElementById('image-viewer-img');
    if (!img) return;

    const rot = ((this.viewerRotation % 360) + 360) % 360;
    const isRotated90or270 = (rot === 90 || rot === 270);

    if (isRotated90or270) {
      const availW = window.innerWidth - 32;
      const availH = window.innerHeight - 130;

      const imgW = img.naturalWidth || 1;
      const imgH = img.naturalHeight || 1;

      const scale = Math.min(availW / imgH, availH / imgW, 2.5);
      img.style.transform = `rotate(${rot}deg) scale(${scale})`;
      img.style.maxWidth = 'none';
      img.style.maxHeight = 'none';
    } else {
      img.style.transform = `rotate(${rot}deg) scale(1)`;
      img.style.maxWidth = '100%';
      img.style.maxHeight = '100%';
    }
  }

  rotateImageViewer() {
    this.viewerRotation = (this.viewerRotation + 90) % 360;
    this.updateImageTransform();
  }

  resetImageViewerRotation() {
    this.viewerRotation = 0;
    this.updateImageTransform();
  }

  prevImageViewerPhoto() {
    if (!this.viewerPhotos || this.viewerPhotos.length <= 1) return;
    this.viewerCurrentIndex = (this.viewerCurrentIndex - 1 + this.viewerPhotos.length) % this.viewerPhotos.length;
    this.loadCurrentViewerPhoto();
  }

  nextImageViewerPhoto() {
    if (!this.viewerPhotos || this.viewerPhotos.length <= 1) return;
    this.viewerCurrentIndex = (this.viewerCurrentIndex + 1) % this.viewerPhotos.length;
    this.loadCurrentViewerPhoto();
  }

  goToViewerPhoto(idx) {
    if (idx >= 0 && idx < this.viewerPhotos.length) {
      this.viewerCurrentIndex = idx;
      this.loadCurrentViewerPhoto();
    }
  }

  renderViewerThumbnails() {
    const thumbsBar = document.getElementById('image-viewer-thumbs-bar');
    if (!thumbsBar) return;

    if (!this.viewerPhotos || this.viewerPhotos.length <= 1) {
      thumbsBar.innerHTML = '';
      thumbsBar.classList.add('hidden');
      return;
    }

    thumbsBar.classList.remove('hidden');
    thumbsBar.innerHTML = this.viewerPhotos.map((src, idx) => {
      const isCur = idx === this.viewerCurrentIndex;
      return `
        <div 
          onclick="app.goToViewerPhoto(${idx})"
          class="w-11 h-11 sm:w-12 sm:h-12 rounded-xl overflow-hidden border-2 cursor-pointer transition-all shrink-0 ${isCur ? 'border-blue-500 scale-110 shadow-lg ring-2 ring-blue-400/50' : 'border-white/30 opacity-60 hover:opacity-100'}"
        >
          <img src="${src}" class="w-full h-full object-cover" alt="Miniatura ${idx + 1}">
        </div>
      `;
    }).join('');
  }

  closeImageViewer() {
    const modal = document.getElementById('image-viewer-modal');
    if (modal) modal.classList.add('hidden');
    this.viewerPhotos = [];
    this.viewerCurrentIndex = 0;
    this.viewerRotation = 0;
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
      version: APP_VERSION,
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
    this.showToast('Backup JSON completo (con tutte le foto) scaricato!', 'success');
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

        // Normalizzazione profonda di tutte le proprietà (foto, audio, lucchetto, meteo, luogo, cartella) per IndexedDB
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
            audio: typeof n.audio === 'string' ? n.audio : null,
            locked: Boolean(n.locked),
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

  // --- UTILIZZO TOKEN AI & STATISTICHE MEMORIA DB (MB) ---
  getAiTokenUsage() {
    const savedTokens = parseInt(localStorage.getItem('massinote_ai_tokens_total') || '0', 10);
    const savedAudioCount = parseInt(localStorage.getItem('massinote_ai_audio_count') || '0', 10);
    return {
      totalTokens: isNaN(savedTokens) ? 0 : savedTokens,
      audioCount: isNaN(savedAudioCount) ? 0 : savedAudioCount
    };
  }

  addAiTokenUsage(tokens) {
    const current = this.getAiTokenUsage();
    const newTotal = current.totalTokens + (parseInt(tokens, 10) || 0);
    const newCount = current.audioCount + 1;
    localStorage.setItem('massinote_ai_tokens_total', newTotal.toString());
    localStorage.setItem('massinote_ai_audio_count', newCount.toString());
    this.updateAiTokenUI();
  }

  updateAiTokenUI() {
    const { totalTokens, audioCount } = this.getAiTokenUsage();
    const tokenBadge = document.getElementById('ai-tokens-total-badge');
    const audioBadge = document.getElementById('ai-audio-count-badge');
    if (tokenBadge) tokenBadge.textContent = totalTokens.toLocaleString('it-IT');
    if (audioBadge) audioBadge.textContent = audioCount.toLocaleString('it-IT');
  }

  async updateStorageStats() {
    const badge = document.getElementById('storage-usage-badge');
    if (badge) {
      badge.textContent = `${this.notes.length} note archiviate`;
    }

    this.updateAiTokenUI();

    // Calcolo preciso dello spazio occupato dal DB (in MegaBytes)
    let totalBytes = 0;
    try {
      for (const n of this.notes) {
        if (!n) continue;
        totalBytes += (n.title || '').length * 2;
        totalBytes += (n.content || '').length * 2;
        totalBytes += (n.weather || '').length * 2;
        totalBytes += (n.location || '').length * 2;
        totalBytes += (n.folder || '').length * 2;
        if (n.audio && typeof n.audio === 'string') {
          totalBytes += n.audio.length;
        }
        if (Array.isArray(n.photos)) {
          for (const p of n.photos) {
            if (typeof p === 'string') totalBytes += p.length;
          }
        }
        totalBytes += 128; // overhead record IndexedDB
      }

      if (navigator.storage && navigator.storage.estimate) {
        const est = await navigator.storage.estimate();
        if (est.usage && est.usage > totalBytes) {
          totalBytes = est.usage;
        }
      }
    } catch (e) {
      console.warn('Storage size estimation error:', e);
    }

    const megabytes = (totalBytes / (1024 * 1024)).toFixed(2);
    const statDbSizeEl = document.getElementById('stat-db-size');
    if (statDbSizeEl) {
      statDbSizeEl.textContent = `${megabytes} MB`;
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
      const viewerModal = document.getElementById('image-viewer-modal');
      const isViewerOpen = viewerModal && !viewerModal.classList.contains('hidden');

      // Escape chiude editor o modali
      if (e.key === 'Escape') {
        this.closeEditor();
        this.closeImageViewer();
        this.closeConfirmModal();
        this.cancelVoiceRecording();
        this.closeAiSearchModal();
        this.closeNotePinModal();
      }

      // Navigazione frecce e rotazione quando il visualizzatore foto è aperto
      if (isViewerOpen) {
        if (e.key === 'ArrowLeft') {
          e.preventDefault();
          this.prevImageViewerPhoto();
        } else if (e.key === 'ArrowRight') {
          e.preventDefault();
          this.nextImageViewerPhoto();
        } else if (e.key === 'r' || e.key === 'R') {
          e.preventDefault();
          this.rotateImageViewer();
        }
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

    // Touch Swipe Gestures per il visualizzatore foto su Smartphone/Tablet
    const viewerModal = document.getElementById('image-viewer-modal');
    if (viewerModal) {
      viewerModal.addEventListener('touchstart', (e) => {
        if (e.touches && e.touches.length === 1) {
          this.viewerTouchStartX = e.touches[0].clientX;
          this.viewerTouchStartY = e.touches[0].clientY;
        }
      }, { passive: true });

      viewerModal.addEventListener('touchend', (e) => {
        if (e.changedTouches && e.changedTouches.length === 1) {
          const endX = e.changedTouches[0].clientX;
          const endY = e.changedTouches[0].clientY;
          const diffX = endX - this.viewerTouchStartX;
          const diffY = endY - this.viewerTouchStartY;

          if (Math.abs(diffX) > 40 && Math.abs(diffX) > Math.abs(diffY)) {
            if (diffX < 0) {
              // Swipe verso sinistra -> foto successiva
              this.nextImageViewerPhoto();
            } else {
              // Swipe verso destra -> foto precedente
              this.prevImageViewerPhoto();
            }
          }
        }
      }, { passive: true });
    }

    // 3. Listener per input PIN nota protetta
    const notePinInput = document.getElementById('note-pin-input');
    if (notePinInput) {
      notePinInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.verifyNotePin();
        }
      });
      notePinInput.addEventListener('input', () => {
        if (notePinInput.value.length >= 4) {
          this.verifyNotePin();
        }
      });
    }

    // 4. Listener Invio su barra di ricerca
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          if (this.isAiSearchActive) {
            e.preventDefault();
            this.performAiSearch(searchInput.value);
          }
        }
      });
    }

    // 4. Drag and Drop globale di file JSON
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
