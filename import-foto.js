/**
 * Importatore & Visualizzatore Foto per "Diario" (MassiNote)
 * Analizza file Word (.DOCX), archivi ZIP e JSON
 * Abbina le fotografie alle note del Diario e salva su Firebase Firestore (SDK + REST API)
 */

// ================= SICUREZZA, VAULT CIFRATO & CHIAVI DINAMICHE =================
const _0xSEC_VAULT = [214, 74, 98, 91, 181, 245, 187, 73, 133, 128, 229, 142, 2, 97, 217, 247, 9, 75, 21, 143, 10, 7, 80, 208, 156, 225, 121, 35, 128, 68, 165, 82, 179, 64, 175, 82, 224, 68, 156, 91, 3, 196, 91, 115, 79, 222, 10, 221, 119, 159, 36, 230, 53, 106, 81, 238, 37, 28, 39, 123, 153, 86, 113, 48, 215, 179, 227, 81, 222, 140, 200, 157, 119, 42, 140, 195, 94, 7, 51, 247, 44, 251, 88, 238, 133, 201, 101, 30, 180, 125, 242, 23, 130, 11, 191, 66, 255, 45, 134, 120, 4, 202, 26, 98, 247, 239, 22, 168, 68, 198, 172, 149, 49, 59, 101, 193, 73, 56, 114, 23, 140, 228, 62, 107, 143, 197, 210, 58, 207, 212, 206, 141, 4, 125, 204, 136, 102, 224, 32, 136, 118, 244, 32, 185, 209, 152, 118, 250, 147, 112, 153, 227, 144, 84, 167, 66, 250, 63, 149, 81, 161, 129, 167, 60, 242, 189, 241, 254, 86, 130, 233, 160, 107, 50, 14, 217, 64, 7, 48, 14, 184, 162, 78, 52, 201, 150, 221, 55, 184, 96, 202, 127, 2, 90, 165, 158, 50, 161, 58, 130, 23, 131, 121, 135, 43, 169, 5, 230, 128, 74, 144, 231, 109, 90, 162, 38, 203, 4, 153, 67, 198, 163, 177, 16, 191, 251, 185, 230, 115, 196, 172, 245, 25, 87, 23, 255, 13, 76, 11, 87, 253, 186, 85, 25, 183, 182, 175, 64, 237, 49, 231, 38, 67, 0, 233, 55, 91, 175, 95, 204, 71, 149, 88, 133, 44, 234, 27, 196, 157, 13, 103, 168, 106, 123, 200, 118, 213, 91, 60, 15, 255, 231, 169, 0, 154, 209, 251, 221, 123, 109, 145, 225, 21, 67, 27, 240, 42, 228, 84, 244, 156, 214, 37, 24, 182, 101, 163, 39, 135, 63, 235, 3, 167, 7, 241, 93, 55, 229, 55, 90, 74, 232, 84, 141, 113, 254, 5, 129, 43, 97, 104, 195, 118, 60, 103, 50, 159, 66, 52, 107, 230, 142, 133, 3, 213, 201, 247, 185, 111, 94, 210, 182, 41, 12, 44, 243, 6, 160, 9, 192, 160, 211, 26, 219, 154, 77, 128, 28, 172, 79, 148, 25, 245, 22, 140, 68, 28, 196, 50, 111, 227, 148, 73, 173, 102, 160, 220, 192, 65, 2, 40, 254, 64, 67, 104];
const _0xSEC_SALT = [173, 91, 234, 18, 99, 142, 77, 215, 63, 108, 19, 88];

let _cachedSecData = null;
function getDecryptedFirebaseConfig() {
  if (_cachedSecData) return _cachedSecData.fb || {};
  try {
    const chars = [];
    for (let i = 0; i < _0xSEC_VAULT.length; i++) {
      const k = (_0xSEC_SALT[i % _0xSEC_SALT.length] + ((i * 13) % 256)) % 256;
      chars.push(String.fromCharCode(_0xSEC_VAULT[i] ^ k));
    }
    _cachedSecData = JSON.parse(chars.join(''));
    return _cachedSecData.fb || {};
  } catch (e) {
    console.error('Credential vault error:', e);
    return {};
  }
}

// ================= UTILITY DATE & TESTO =================
const ITALIAN_MONTHS = [
  'Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno',
  'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'
];
const ITALIAN_DAYS = ['Domenica', 'Lunedì', 'Martedì', 'Mercoledì', 'Giovedì', 'Venerdì', 'Sabato'];

function formatItalianFull(dateInput) {
  if (!dateInput) return 'Data non specificata';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return 'Data non valida';
  const day = String(d.getDate()).padStart(2, '0');
  const month = ITALIAN_MONTHS[d.getMonth()];
  const year = d.getFullYear();
  const weekday = ITALIAN_DAYS[d.getDay()];
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  return `${weekday} ${day} ${month} ${year}, ${hours}:${minutes}`;
}

// ================= CLASSE PRINCIPALE IMPORTATORE =================
class PhotoImporterApp {
  constructor() {
    this.firebaseConfig = getDecryptedFirebaseConfig();
    this.apiKey = this.firebaseConfig.apiKey || '';
    this.projectId = this.firebaseConfig.projectId || 'app-create-con-ai';

    this.firebaseApp = null;
    this.auth = null;
    this.db = null;
    this.isOnline = false;

    // Dati in memoria
    this.firebaseNotes = []; // Tutte le note caricate da Firestore
    this.allExtractedPhotos = []; // Tutte le foto estratte dal file
    this.orphanPhotos = [];  // Foto trovate ma non ancora collegate a una nota
    this.docxExtractedNotes = [];

    this.currentFilter = 'matched'; // 'matched', 'all', 'unmatched', 'orphans'
    this.searchQuery = '';
    this.matchingTolerance = '5min'; // 'exact', '5min', '1hour', 'sameday'

    this.activeAssignPhoto = null; // Foto selezionata per assegnazione manuale

    this.init();
  }

  async init() {
    this.setupGlobalDragAndDrop();
    this.setupDropzone();
    this.setupEventListeners();
    await this.loadFirebaseNotes();
  }

  // --- PREVIENI COMPORTAMENTO DEFAULT DRAG & DROP BROWSER ---
  setupGlobalDragAndDrop() {
    // Impedisce al browser di aprire il file se viene rilasciato fuori dal riquadro
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, false);

    window.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, false);
  }

  setupDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('backup-file-input');
    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('click', (e) => {
      // Se non si è cliccato direttamente su un pulsante o link interno
      if (e.target.tagName !== 'BUTTON' && !e.target.closest('button')) {
        fileInput.click();
      }
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('border-blue-500', 'bg-blue-50/70', 'dark:bg-blue-950/50', 'scale-[1.01]');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-blue-500', 'bg-blue-50/70', 'dark:bg-blue-950/50', 'scale-[1.01]');
      }, false);
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const dt = e.dataTransfer;
      const files = dt && dt.files;
      if (files && files.length > 0) {
        console.log(`File rilasciato tramite drag & drop: ${files[0].name} (${files[0].size} bytes)`);
        this.processUploadedFiles(files);
      }
    });
  }

  setupEventListeners() {
    if (window.lucide) lucide.createIcons();
  }

  handleFileSelect(event) {
    const files = event.target.files;
    if (files && files.length > 0) {
      console.log(`File selezionato da input: ${files[0].name} (${files[0].size} bytes)`);
      this.processUploadedFiles(files);
    }
    event.target.value = '';
  }

  // --- CARICAMENTO NOTE FIREBASE (REST API VELOCE + SDK FALLBACK) ---
  async loadFirebaseNotes() {
    const statusDot = document.getElementById('cloud-status-dot');
    const statusText = document.getElementById('cloud-status-text');
    const statusBadge = document.getElementById('cloud-status-badge');
    const totalCountEl = document.getElementById('stat-total-firebase-notes');
    const withPhotosEl = document.getElementById('stat-notes-already-photos');

    if (totalCountEl) totalCountEl.textContent = 'Scaricamento note...';
    if (statusText) statusText.textContent = 'Scaricamento note da Firebase...';
    if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-amber-500 animate-pulse';

    try {
      // 1. Prova prima il caricamento istantaneo tramite Firestore REST API
      const notes = await this.fetchNotesViaRestApi();

      this.firebaseNotes = notes;
      this.isOnline = true;

      if (statusBadge) {
        statusBadge.className = 'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900/50';
      }
      if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-emerald-500';
      if (statusText) statusText.textContent = `Firebase Cloud Connesso (${notes.length} note)`;

      const alreadyPhotosCount = notes.filter(n => n.photos && n.photos.length > 0).length;
      if (totalCountEl) totalCountEl.textContent = `${notes.length} note`;
      if (withPhotosEl) withPhotosEl.textContent = `${alreadyPhotosCount} note`;
      
      const badgeTotal = document.getElementById('badge-total-notes');
      if (badgeTotal) badgeTotal.textContent = notes.length;

      this.updateCounters();
      this.renderNotesVerificationList();
      this.showToast(`Caricate con successo ${notes.length} note dal Cloud Firebase!`, 'success');

      // Prova anche inizializzazione SDK in background (non bloccante)
      this.initFirebaseSdkInBackground();
    } catch (restErr) {
      console.warn('REST API fetch error, provo SDK Firebase:', restErr);
      try {
        await this.loadNotesViaSdk();
      } catch (sdkErr) {
        console.error('Entrambi i metodi di caricamento Firebase sono falliti:', sdkErr);
        if (statusBadge) {
          statusBadge.className = 'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-200 dark:bg-red-950/40 dark:text-red-400 dark:border-red-900/50';
        }
        if (statusDot) statusDot.className = 'w-2 h-2 rounded-full bg-red-500';
        if (statusText) statusText.textContent = 'Errore Connessione Firebase';
        if (totalCountEl) totalCountEl.textContent = 'Errore';
        this.showToast('Impossibile scaricare le note da Firebase. Verifica la connessione.', 'error');
      }
    }
  }

  async fetchNotesViaRestApi() {
    let allDocs = [];
    let pageToken = null;

    do {
      let url = `https://firestore.googleapis.com/v1/projects/${this.projectId}/databases/(default)/documents/notes?key=${this.apiKey}&pageSize=300`;
      if (pageToken) {
        url += `&pageToken=${encodeURIComponent(pageToken)}`;
      }

      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.documents && Array.isArray(data.documents)) {
        allDocs = allDocs.concat(data.documents);
      }
      pageToken = data.nextPageToken || null;
    } while (pageToken);

    // Converti documenti Firestore REST in oggetti nota standard
    const notes = allDocs.map(doc => {
      const docId = doc.name.split('/').pop();
      const fields = doc.fields || {};
      
      const getString = (f) => (fields[f] && fields[f].stringValue !== undefined) ? fields[f].stringValue : '';
      const getArray = (f) => {
        if (!fields[f] || !fields[f].arrayValue || !fields[f].arrayValue.values) return [];
        return fields[f].arrayValue.values.map(v => v.stringValue || v.referenceValue || '');
      };

      const photosArr = getArray('photos');
      const tagsArr = getArray('tags');

      return {
        id: docId,
        title: getString('title'),
        content: getString('content'),
        date: getString('date') || getString('createdAt') || new Date().toISOString(),
        weather: getString('weather'),
        location: getString('location'),
        folder: getString('folder'),
        tags: tagsArr,
        photos: photosArr,
        initialPhotosCount: photosArr.length,
        pendingPhotos: []
      };
    });

    notes.sort((a, b) => new Date(b.date) - new Date(a.date));
    return notes;
  }

  async initFirebaseSdkInBackground() {
    try {
      if (typeof firebase === 'undefined') return;
      if (!firebase.apps.length) {
        this.firebaseApp = firebase.initializeApp(this.firebaseConfig);
      } else {
        this.firebaseApp = firebase.app();
      }
      this.auth = firebase.auth();
      this.db = firebase.firestore();
      if (this.auth && !this.auth.currentUser) {
        await this.auth.signInAnonymously().catch(e => console.warn('Auth anonima SDK avviso:', e));
      }
    } catch (e) {
      console.warn('Inizializzazione SDK Firebase in background non riuscita:', e);
    }
  }

  async loadNotesViaSdk() {
    if (typeof firebase === 'undefined') throw new Error('SDK Firebase non caricato.');
    if (!this.firebaseApp) {
      this.firebaseApp = firebase.apps.length ? firebase.app() : firebase.initializeApp(this.firebaseConfig);
      this.auth = firebase.auth();
      this.db = firebase.firestore();
    }

    const snapshot = await this.db.collection('notes').get();
    const notes = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      notes.push({
        id: doc.id,
        title: data.title || '',
        content: data.content || '',
        date: data.date || data.createdAt || new Date().toISOString(),
        weather: data.weather || '',
        location: data.location || '',
        folder: data.folder || '',
        tags: Array.isArray(data.tags) ? data.tags : [],
        photos: Array.isArray(data.photos) ? [...data.photos] : [],
        initialPhotosCount: Array.isArray(data.photos) ? data.photos.length : 0,
        pendingPhotos: []
      });
    });

    notes.sort((a, b) => new Date(b.date) - new Date(a.date));
    this.firebaseNotes = notes;
  }

  // --- GESTIONE ED ELABORAZIONE FILE CARICATI ---
  async processUploadedFiles(fileList) {
    if (!fileList || fileList.length === 0) return;

    const firstFile = fileList[0];
    const fileNameEl = document.getElementById('current-file-name');
    if (fileNameEl) {
      fileNameEl.textContent = fileList.length === 1 
        ? `${firstFile.name} (${Math.round(firstFile.size / 1024)} KB)` 
        : `${fileList.length} file selezionati`;
    }

    this.showToast('Elaborazione del backup in corso...', 'info');

    // Resetta liste di foto e pendenti
    this.allExtractedPhotos = [];
    this.orphanPhotos = [];
    this.firebaseNotes.forEach(n => { n.pendingPhotos = []; });

    try {
      const lowerName = firstFile.name.toLowerCase();

      // Riconoscimento formato
      if (lowerName.endsWith('.docx') || lowerName.endsWith('.doc')) {
        await this.parseDocxBackup(firstFile);
      } else if (lowerName.endsWith('.zip') || lowerName.endsWith('.diaro') || (fileList.length === 1 && firstFile.type.includes('zip'))) {
        await this.parseZipBackup(firstFile);
      } else if (lowerName.endsWith('.json')) {
        await this.parseJsonBackup(firstFile);
      } else {
        await this.parseLooseImageFiles(fileList);
      }

      // Esegui abbinamento con le note Firestore
      this.executeMatching();
      this.updateCounters();
      this.renderNotesVerificationList();

      const matchedCount = this.firebaseNotes.filter(n => n.pendingPhotos.length > 0).length;
      this.showToast(`Analisi completata! Trovate ${this.allExtractedPhotos.length} foto, abbinate a ${matchedCount} note.`, 'success');
    } catch (err) {
      console.error('Errore elaborazione backup:', err);
      this.showToast('Errore durante l\'analisi del file: ' + err.message, 'error');
    }
  }

  // ================= PARSER WORD DOCX (.DOCX ARCHIVE) =================
  getParagraphText(pNode) {
    if (!pNode) return '';
    let text = '';
    const allDescendants = pNode.getElementsByTagName('*');
    for (let i = 0; i < allDescendants.length; i++) {
      const el = allDescendants[i];
      const name = el.localName || el.nodeName.split(':').pop();
      if (name === 't') {
        text += el.textContent || '';
      } else if (name === 'tab') {
        text += '\t';
      } else if (name === 'br' || name === 'cr') {
        text += '\n';
      }
    }
    return text;
  }

  getParagraphImageIds(pNode) {
    if (!pNode) return [];
    const rIds = [];
    const allDescendants = pNode.getElementsByTagName('*');
    for (let i = 0; i < allDescendants.length; i++) {
      const el = allDescendants[i];
      const rEmbed = el.getAttribute('r:embed') || el.getAttribute('r:link') || el.getAttribute('r:id') || el.getAttribute('o:relid');
      if (rEmbed && !rIds.includes(rEmbed)) {
        rIds.push(rEmbed);
      }
      for (let a = 0; a < el.attributes.length; a++) {
        const attr = el.attributes[a];
        if (attr.name.includes('embed') || attr.name.includes('relid') || attr.name.endsWith(':id') || attr.name === 'id') {
          if (attr.value && attr.value.startsWith('rId') && !rIds.includes(attr.value)) {
            rIds.push(attr.value);
          }
        }
      }
    }
    return rIds;
  }

  parseNoteDateHeader(line) {
    if (!line || typeof line !== 'string') return null;
    const str = line.trim();

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

    // 1. Formato DOCX Utente: "12  Mercoledì / Agosto 2026 10:16" o con \t
    const pat1 = /^\s*(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\s*[\/\-]\s*([A-Za-zÀ-ÿ]+)\s+(\d{4})\s*[\t\s,]+(\d{1,2}):(\d{2})/i;
    const m1 = str.match(pat1);
    if (m1) {
      const day = parseInt(m1[1], 10);
      const weekday = m1[2];
      const monthStr = m1[3].toLowerCase();
      const year = parseInt(m1[4], 10);
      const hours = parseInt(m1[5], 10);
      const minutes = parseInt(m1[6], 10);
      const monthIndex = monthMap[monthStr] !== undefined ? monthMap[monthStr] : 0;
      return {
        day, monthIndex, year, hours, minutes, weekday,
        dateObj: new Date(year, monthIndex, day, hours, minutes),
        timestamp: new Date(year, monthIndex, day, hours, minutes).getTime()
      };
    }

    // 2. Formato standard italiano: "12 Agosto 2026, Mercoledì 10:16" o "20 Febbraio 2013, 15:33"
    const pat2 = /^\s*(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\s+(\d{4})(?:[,\s]+([A-Za-zÀ-ÿ]+))?\s*[\t\s,]+(\d{1,2}):(\d{2})/i;
    const m2 = str.match(pat2);
    if (m2) {
      const day = parseInt(m2[1], 10);
      const monthStr = m2[2].toLowerCase();
      const year = parseInt(m2[3], 10);
      const weekday = m2[4] || '';
      const hours = parseInt(m2[5], 10);
      const minutes = parseInt(m2[6], 10);
      const monthIndex = monthMap[monthStr] !== undefined ? monthMap[monthStr] : 0;
      return {
        day, monthIndex, year, hours, minutes, weekday,
        dateObj: new Date(year, monthIndex, day, hours, minutes),
        timestamp: new Date(year, monthIndex, day, hours, minutes).getTime()
      };
    }

    // 3. Formato con giorno della settimana prima: "Mercoledì 12 Agosto 2026, 10:16"
    const pat3 = /^\s*([A-Za-zÀ-ÿ]+)\s+(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\s+(\d{4})\s*[\t\s,]+(\d{1,2}):(\d{2})/i;
    const m3 = str.match(pat3);
    if (m3) {
      const weekday = m3[1];
      const day = parseInt(m3[2], 10);
      const monthStr = m3[3].toLowerCase();
      const year = parseInt(m3[4], 10);
      const hours = parseInt(m3[5], 10);
      const minutes = parseInt(m3[6], 10);
      const monthIndex = monthMap[monthStr] !== undefined ? monthMap[monthStr] : 0;
      return {
        day, monthIndex, year, hours, minutes, weekday,
        dateObj: new Date(year, monthIndex, day, hours, minutes),
        timestamp: new Date(year, monthIndex, day, hours, minutes).getTime()
      };
    }

    // 4. Formato solo data (se manca l'ora): "12  Mercoledì / Agosto 2026"
    const pat4 = /^\s*(\d{1,2})\s+([A-Za-zÀ-ÿ]+)\s*[\/\-]\s*([A-Za-zÀ-ÿ]+)\s+(\d{4})\s*$/i;
    const m4 = str.match(pat4);
    if (m4) {
      const day = parseInt(m4[1], 10);
      const weekday = m4[2];
      const monthStr = m4[3].toLowerCase();
      const year = parseInt(m4[4], 10);
      const monthIndex = monthMap[monthStr] !== undefined ? monthMap[monthStr] : 0;
      return {
        day, monthIndex, year, hours: 12, minutes: 0, weekday,
        dateObj: new Date(year, monthIndex, day, 12, 0),
        timestamp: new Date(year, monthIndex, day, 12, 0).getTime()
      };
    }

    return null;
  }

  async parseDocxBackup(docxFile) {
    if (typeof JSZip === 'undefined') {
      throw new Error('Libreria JSZip non caricata nel browser.');
    }

    console.log('Avvio analisi file Word .DOCX:', docxFile.name);
    const zip = await JSZip.loadAsync(docxFile);
    const fileKeys = Object.keys(zip.files);

    // 1. Mappa delle relazioni immagine (word/_rels/document.xml.rels)
    const relsKey = fileKeys.find(k => k.toLowerCase() === 'word/_rels/document.xml.rels');
    const relsMap = {};

    if (relsKey && zip.files[relsKey]) {
      const relsXmlText = await zip.files[relsKey].async('text');
      const parser = new DOMParser();
      const relsDoc = parser.parseFromString(relsXmlText, 'application/xml');
      const relNodes = relsDoc.getElementsByTagName('Relationship');
      for (let i = 0; i < relNodes.length; i++) {
        const rId = relNodes[i].getAttribute('Id');
        let target = relNodes[i].getAttribute('Target');
        if (rId && target) {
          if (!target.startsWith('word/')) {
            target = 'word/' + target.replace(/^\.\//, '');
          }
          relsMap[rId] = target;
        }
      }
    }

    // 2. Estrai in memoria tutte le immagini (ESCLUDENDO esplicitamente i file .PNG)
    const imageCache = {};
    for (const [rId, targetPath] of Object.entries(relsMap)) {
      const zipKey = fileKeys.find(k => k.toLowerCase() === targetPath.toLowerCase() || k.toLowerCase().endsWith(targetPath.toLowerCase().replace('word/', '')));
      if (zipKey && zip.files[zipKey]) {
        const ext = zipKey.split('.').pop().toLowerCase();
        
        // Ignora immagini in formato .png
        if (ext === 'png') {
          console.log(`Ignorata immagine PNG di sistema/decorazione: ${zipKey}`);
          continue;
        }

        const mime = ext === 'webp' ? 'image/webp' : (ext === 'gif' ? 'image/gif' : 'image/jpeg');
        const base64 = await zip.files[zipKey].async('base64');
        const dataUrl = `data:${mime};base64,${base64}`;
        const rawName = zipKey.split('/').pop();
        imageCache[rId] = {
          rId: rId,
          name: rawName,
          dataUrl: dataUrl,
          zipKey: zipKey
        };
      }
    }

    // 3. Flusso dei paragrafi in word/document.xml
    const docKey = fileKeys.find(k => k.toLowerCase() === 'word/document.xml');
    if (!docKey || !zip.files[docKey]) {
      throw new Error('File word/document.xml non trovato nel documento DOCX.');
    }

    const docXmlText = await zip.files[docKey].async('text');
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(docXmlText, 'application/xml');

    const pNodes = xmlDoc.getElementsByTagName('w:p');
    const extractedNotes = [];
    let currentNote = null;

    for (let i = 0; i < pNodes.length; i++) {
      const pNode = pNodes[i];
      const pText = this.getParagraphText(pNode).trim();
      const pImageRIds = this.getParagraphImageIds(pNode);

      const dateHeaderInfo = this.parseNoteDateHeader(pText);
      const isSeparator = pText.length >= 30 && /^-(?:-{29,})$/.test(pText);

      // Se troviamo l'inizio di una nuova nota (data e ora) o un separatore principale
      if (dateHeaderInfo || (isSeparator && currentNote !== null)) {
        if (currentNote !== null) {
          extractedNotes.push(currentNote);
          currentNote = null;
        }

        if (dateHeaderInfo) {
          currentNote = {
            id: 'docx_' + dateHeaderInfo.timestamp + '_' + i,
            day: dateHeaderInfo.day,
            monthIndex: dateHeaderInfo.monthIndex,
            year: dateHeaderInfo.year,
            hours: dateHeaderInfo.hours,
            minutes: dateHeaderInfo.minutes,
            weekday: dateHeaderInfo.weekday,
            dateObj: dateHeaderInfo.dateObj,
            timestamp: dateHeaderInfo.timestamp,
            dateStr: pText,
            rawTextLines: [],
            title: '',
            content: '',
            photos: []
          };
        }
        continue;
      }

      // Se troviamo contenuti prima della prima data
      if (currentNote === null && (pText.length > 0 || pImageRIds.length > 0)) {
        currentNote = {
          id: 'docx_initial_' + i,
          day: null, monthIndex: null, year: null, hours: null, minutes: null, weekday: '',
          dateObj: null, timestamp: null, dateStr: '',
          rawTextLines: [], title: '', content: '', photos: []
        };
      }

      // Se siamo all'interno di una nota:
      if (currentNote !== null) {
        if (pText.length > 0) {
          currentNote.rawTextLines.push(pText);
        }

        // Tutte le immagini presenti fino alla nota successiva appartengono a QUESTA nota
        for (const rId of pImageRIds) {
          const imgInfo = imageCache[rId];
          if (imgInfo) {
            const photoItem = {
              id: 'photo_docx_' + Math.random().toString(36).substr(2, 9),
              rId: rId,
              name: imgInfo.name,
              dataUrl: imgInfo.dataUrl,
              dateObj: currentNote.dateObj,
              timestamp: currentNote.timestamp,
              docxNote: currentNote,
              matchType: 'Foto nota DOCX (' + (currentNote.dateStr || 'Nota') + ')'
            };
            currentNote.photos.push(photoItem);
            this.allExtractedPhotos.push(photoItem);
          }
        }
      }
    }

    if (currentNote !== null) {
      extractedNotes.push(currentNote);
    }

    // Estrazione titoli e testi puliti
    const titleRegex = /:::\s*([\s\S]*?)\s*:::/;
    for (const n of extractedNotes) {
      const fullText = n.rawTextLines.join('\n').trim();
      const tMatch = fullText.match(titleRegex);
      if (tMatch) {
        n.title = tMatch[1].trim();
        n.content = fullText.replace(tMatch[0], '').trim();
      } else {
        const firstLine = n.rawTextLines[0] || '';
        if (firstLine && firstLine.length < 60) {
          n.title = firstLine;
          n.content = n.rawTextLines.slice(1).join('\n').trim();
        } else {
          n.content = fullText;
        }
      }

      for (const p of n.photos) {
        p.docxNoteTitle = n.title;
        p.docxNoteContent = n.content;
      }
    }

    this.docxExtractedNotes = extractedNotes;
    console.log(`Analisi DOCX completata: ${extractedNotes.length} note estratte, ${extractedNotes.filter(n => n.photos.length > 0).length} con foto, ${this.allExtractedPhotos.length} foto totali.`);
  }

  // ================= PARSER ZIP / DIARO BACKUP =================
  async parseZipBackup(zipFile) {
    if (typeof JSZip === 'undefined') throw new Error('Libreria JSZip non caricata.');

    const zip = await JSZip.loadAsync(zipFile);
    const fileKeys = Object.keys(zip.files);

    const imageExtensions = ['.jpg', '.jpeg', '.webp', '.gif', '.bmp']; // Esclusi file .png
    const imageFiles = fileKeys.filter(k => {
      const lower = k.toLowerCase();
      return !zip.files[k].dir && !lower.endsWith('.png') && imageExtensions.some(ext => lower.endsWith(ext));
    });

    for (const imgKey of imageFiles) {
      const fileObj = zip.files[imgKey];
      const base64 = await fileObj.async('base64');
      const ext = imgKey.split('.').pop().toLowerCase();
      if (ext === 'png') continue;
      const mime = ext === 'webp' ? 'image/webp' : 'image/jpeg';
      const dataUrl = `data:${mime};base64,${base64}`;

      const rawFileName = imgKey.split('/').pop();
      const photoItem = {
        id: 'photo_' + Math.random().toString(36).substr(2, 9),
        zipPath: imgKey,
        name: rawFileName,
        dataUrl: dataUrl,
        dateObj: fileObj.date || null,
        timestamp: null,
        matchType: null
      };

      const tsFromFilename = this.extractTimestampFromFilename(rawFileName);
      if (tsFromFilename) {
        photoItem.timestamp = tsFromFilename.timestamp;
        photoItem.dateObj = tsFromFilename.dateObj;
      }

      this.allExtractedPhotos.push(photoItem);
    }
  }

  async parseJsonBackup(jsonFile) {
    const text = await jsonFile.text();
    const data = JSON.parse(text);
    const notesArray = Array.isArray(data) ? data : (data.notes || []);

    for (const item of notesArray) {
      const photos = item.photos || item.images || [];
      if (Array.isArray(photos)) {
        for (let i = 0; i < photos.length; i++) {
          const p = photos[i];
          const dataUrl = typeof p === 'string' ? p : (p.dataUrl || p.url || '');
          if (!dataUrl || dataUrl.startsWith('data:image/png')) continue;

          const photoItem = {
            id: 'photo_json_' + Math.random().toString(36).substr(2, 9),
            name: `Foto_${item.title || 'nota'}_${i+1}.jpg`,
            dataUrl: dataUrl,
            dateObj: item.date ? new Date(item.date) : null,
            timestamp: item.date ? new Date(item.date).getTime() : null,
            directNoteId: item.id || null,
            directNoteTitle: item.title || '',
            directNoteDate: item.date || ''
          };
          this.allExtractedPhotos.push(photoItem);
        }
      }
    }
  }

  async parseLooseImageFiles(fileList) {
    for (let i = 0; i < fileList.length; i++) {
      const file = fileList[i];
      if (!file.type.startsWith('image/') || file.type === 'image/png' || file.name.toLowerCase().endsWith('.png')) continue;

      const dataUrl = await this.fileToDataUrl(file);
      const photoItem = {
        id: 'photo_file_' + Math.random().toString(36).substr(2, 9),
        name: file.name,
        dataUrl: dataUrl,
        dateObj: file.lastModified ? new Date(file.lastModified) : null,
        timestamp: file.lastModified || null
      };

      const tsFromFilename = this.extractTimestampFromFilename(file.name);
      if (tsFromFilename) {
        photoItem.timestamp = tsFromFilename.timestamp;
        photoItem.dateObj = tsFromFilename.dateObj;
      }

      this.allExtractedPhotos.push(photoItem);
    }
  }

  extractTimestampFromFilename(filename) {
    if (!filename) return null;
    const clean = filename.replace(/\.[^/.]+$/, '');
    const msMatch = clean.match(/(\d{13})/);
    if (msMatch) {
      const ts = parseInt(msMatch[1], 10);
      const d = new Date(ts);
      if (!isNaN(d.getTime()) && d.getFullYear() >= 2000 && d.getFullYear() <= 2035) {
        return { timestamp: ts, dateObj: d };
      }
    }
    return null;
  }

  // ================= MOTORE DI ABBINAMENTO (MATCHING ENGINE) =================
  executeMatching() {
    this.firebaseNotes.forEach(n => { n.pendingPhotos = []; });
    this.orphanPhotos = [];

    const toleranceSetting = document.getElementById('matching-tolerance')?.value || this.matchingTolerance;

    for (const photo of this.allExtractedPhotos) {
      let matchedNote = null;
      let matchReason = '';

      // 1. Abbinamento da DOCX Note
      if (photo.docxNote) {
        const dn = photo.docxNote;

        // 1a. Corrispondenza Data e Ora esatta
        if (dn.year !== null && dn.day !== null) {
          matchedNote = this.firebaseNotes.find(n => {
            if (!n.date) return false;
            if (dn.timestamp && n.id && n.id.includes(String(dn.timestamp))) return true;

            const fd = new Date(n.date);
            if (isNaN(fd.getTime())) return false;

            // Confronto data UTC
            const isUtcDateMatch = (
              fd.getUTCFullYear() === dn.year &&
              fd.getUTCMonth() === dn.monthIndex &&
              fd.getUTCDate() === dn.day
            );
            const utcTimeDiff = Math.abs((fd.getUTCHours() * 60 + fd.getUTCMinutes()) - (dn.hours * 60 + dn.minutes));
            if (isUtcDateMatch && utcTimeDiff <= 3) return true;

            // Confronto data Locale
            const isLocalDateMatch = (
              fd.getFullYear() === dn.year &&
              fd.getMonth() === dn.monthIndex &&
              fd.getDate() === dn.day
            );
            const localTimeDiff = Math.abs((fd.getHours() * 60 + fd.getMinutes()) - (dn.hours * 60 + dn.minutes));
            if (isLocalDateMatch && localTimeDiff <= 3) return true;

            return false;
          });

          if (matchedNote) matchReason = 'Documento DOCX (Data e Ora esatta)';
        }

        // 1b. Cerca per titolo
        if (!matchedNote && dn.title && dn.title.length > 2) {
          const dnTitle = dn.title.trim().toLowerCase();
          matchedNote = this.firebaseNotes.find(n => {
            const nt = (n.title || '').trim().toLowerCase();
            return nt === dnTitle || (nt.length > 3 && (nt.includes(dnTitle) || dnTitle.includes(nt)));
          });
          if (matchedNote) matchReason = 'Documento DOCX (Titolo nota: ' + dn.title + ')';
        }

        // 1c. Cerca per contenuto testo
        if (!matchedNote && dn.content && dn.content.length > 15) {
          const sample = dn.content.substring(0, 35).toLowerCase();
          matchedNote = this.firebaseNotes.find(n => (n.content || '').toLowerCase().includes(sample));
          if (matchedNote) matchReason = 'Documento DOCX (Contenuto testo)';
        }

        // 1d. Fallback: stesso giorno
        if (!matchedNote && dn.year !== null && dn.day !== null) {
          let bestDiff = Infinity;
          let candidate = null;
          for (const n of this.firebaseNotes) {
            const fd = new Date(n.date);
            if (isNaN(fd.getTime())) continue;
            const sameDay = (
              (fd.getUTCFullYear() === dn.year && fd.getUTCMonth() === dn.monthIndex && fd.getUTCDate() === dn.day) ||
              (fd.getFullYear() === dn.year && fd.getMonth() === dn.monthIndex && fd.getDate() === dn.day)
            );
            if (sameDay) {
              const diff = dn.timestamp ? Math.abs(fd.getTime() - dn.timestamp) : 0;
              if (diff < bestDiff) {
                bestDiff = diff;
                candidate = n;
              }
            }
          }
          if (candidate) {
            matchedNote = candidate;
            matchReason = 'Documento DOCX (Stesso giorno: ' + dn.day + '/' + (dn.monthIndex+1) + '/' + dn.year + ')';
          }
        }
      }

      // 2. Abbinamento generico per Timestamp
      if (!matchedNote && photo.timestamp) {
        matchedNote = this.firebaseNotes.find(n => n.id && n.id.includes(String(photo.timestamp)));
        if (matchedNote) matchReason = 'Timestamp esatto ID nota';
      }

      // Assegna foto
      if (matchedNote) {
        photo.matchType = matchReason;
        matchedNote.pendingPhotos.push(photo);
      } else {
        this.orphanPhotos.push(photo);
      }
    }
  }

  recalculateMatching() {
    this.executeMatching();
    this.updateCounters();
    this.renderNotesVerificationList();
    this.showToast('Abbinamento ricalcolato!', 'info');
  }

  updateCounters() {
    const totalNotes = this.firebaseNotes.length;
    const totalPhotos = this.allExtractedPhotos.length;
    const matchedNotes = this.firebaseNotes.filter(n => n.pendingPhotos.length > 0);
    const unmatchedNotes = this.firebaseNotes.filter(n => n.pendingPhotos.length === 0);
    const orphanPhotosCount = this.orphanPhotos.length;

    const badgePhotos = document.getElementById('badge-total-photos');
    const badgeMatched = document.getElementById('badge-matched-notes');
    const badgePct = document.getElementById('badge-matched-pct');
    const badgeOrphans = document.getElementById('badge-orphan-photos');

    if (badgePhotos) badgePhotos.textContent = totalPhotos;
    if (badgeMatched) badgeMatched.textContent = matchedNotes.length;
    if (badgePct) {
      const pct = totalNotes > 0 ? Math.round((matchedNotes.length / totalNotes) * 100) : 0;
      badgePct.textContent = `${pct}% delle note`;
    }
    if (badgeOrphans) badgeOrphans.textContent = orphanPhotosCount;

    const fMatched = document.getElementById('filter-count-matched');
    const fAll = document.getElementById('filter-count-all');
    const fUnmatched = document.getElementById('filter-count-unmatched');
    const fOrphans = document.getElementById('filter-count-orphans');

    if (fMatched) fMatched.textContent = matchedNotes.length;
    if (fAll) fAll.textContent = totalNotes;
    if (fUnmatched) fUnmatched.textContent = unmatchedNotes.length;
    if (fOrphans) fOrphans.textContent = orphanPhotosCount;

    const btnSaveCount = document.getElementById('btn-save-count');
    if (btnSaveCount) btnSaveCount.textContent = matchedNotes.length;

    const btnSaveTop = document.getElementById('btn-save-cloud-top');
    const btnSaveBottom = document.getElementById('btn-save-cloud-bottom');
    const disableSave = matchedNotes.length === 0;

    if (btnSaveTop) btnSaveTop.disabled = disableSave;
    if (btnSaveBottom) btnSaveBottom.disabled = disableSave;
  }

  // --- FILTRI & RICERCA ---
  setFilter(filterName) {
    this.currentFilter = filterName;

    const buttons = {
      'matched': document.getElementById('filter-btn-matched'),
      'all': document.getElementById('filter-btn-all'),
      'unmatched': document.getElementById('filter-btn-unmatched'),
      'orphans': document.getElementById('filter-btn-orphans')
    };

    Object.keys(buttons).forEach(key => {
      const btn = buttons[key];
      if (!btn) return;
      if (key === filterName) {
        btn.className = 'px-3 py-1.5 rounded-xl bg-blue-600 text-white shadow-sm transition-all whitespace-nowrap';
      } else {
        btn.className = 'px-3 py-1.5 rounded-xl bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-700 transition-all whitespace-nowrap';
      }
    });

    this.renderNotesVerificationList();
  }

  handleSearch(event) {
    this.searchQuery = (event.target.value || '').trim().toLowerCase();
    const clearBtn = document.getElementById('search-clear-btn');
    if (clearBtn) {
      if (this.searchQuery) clearBtn.classList.remove('hidden');
      else clearBtn.classList.add('hidden');
    }
    this.renderNotesVerificationList();
  }

  clearSearch() {
    const input = document.getElementById('search-input');
    if (input) input.value = '';
    this.searchQuery = '';
    const clearBtn = document.getElementById('search-clear-btn');
    if (clearBtn) clearBtn.classList.add('hidden');
    this.renderNotesVerificationList();
  }

  // --- RENDER VISUALE ---
  renderNotesVerificationList() {
    const container = document.getElementById('notes-verification-container');
    if (!container) return;

    if (this.currentFilter === 'orphans') {
      this.renderOrphanPhotosView(container);
      return;
    }

    let list = [...this.firebaseNotes];

    if (this.currentFilter === 'matched') {
      list = list.filter(n => n.pendingPhotos.length > 0);
    } else if (this.currentFilter === 'unmatched') {
      list = list.filter(n => n.pendingPhotos.length === 0);
    }

    if (this.searchQuery) {
      const q = this.searchQuery;
      list = list.filter(n => 
        (n.title && n.title.toLowerCase().includes(q)) ||
        (n.content && n.content.toLowerCase().includes(q)) ||
        (n.date && n.date.toLowerCase().includes(q)) ||
        n.pendingPhotos.some(p => p.name.toLowerCase().includes(q))
      );
    }

    if (list.length === 0) {
      container.innerHTML = `
        <div class="text-center py-16 text-slate-400">
          <i data-lucide="inbox" class="w-12 h-12 mx-auto mb-2 text-slate-300 dark:text-slate-600"></i>
          <p class="text-sm font-semibold">Nessuna nota corrisponde ai filtri selezionati.</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    container.innerHTML = list.map(note => {
      const hasPendingPhotos = note.pendingPhotos.length > 0;
      const alreadyHasPhotos = note.photos && note.photos.length > 0;
      const dateFormatted = formatItalianFull(note.date);

      const photosHtml = hasPendingPhotos ? `
        <div class="space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Foto dal Backup (${note.pendingPhotos.length})
            </span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2.5">
            ${note.pendingPhotos.map((photo, pIdx) => `
              <div class="group relative rounded-xl overflow-hidden bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-sm aspect-square">
                <img src="${photo.dataUrl}" alt="${photo.name}" class="w-full h-full object-cover cursor-pointer hover:scale-105 transition-transform duration-200" onclick="importer.openPhotoViewer('${photo.dataUrl}', '${photo.name} - ${dateFormatted}')">
                
                <div class="absolute top-1 left-1 bg-black/60 backdrop-blur-sm text-white px-1.5 py-0.5 rounded text-[9px] font-bold">
                  ${photo.matchType || 'Abbinata'}
                </div>

                <button onclick="importer.removePhotoFromNote('${note.id}', ${pIdx})" class="absolute top-1 right-1 w-6 h-6 bg-red-600 hover:bg-red-700 text-white rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity shadow-md" title="Rimuovi foto da questa nota">
                  <i data-lucide="x" class="w-3.5 h-3.5"></i>
                </button>

                <div class="absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/80 to-transparent p-1 text-[9px] text-white truncate text-center">
                  ${photo.name}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : `
        <div class="h-full flex flex-col items-center justify-center p-6 border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-xl text-center text-slate-400 text-xs">
          <i data-lucide="image-off" class="w-6 h-6 mb-1.5 stroke-1"></i>
          <span>Nessuna foto dal backup abbinata a questa nota</span>
        </div>
      `;

      return `
        <div class="p-4 sm:p-5 rounded-2xl bg-white dark:bg-slate-900 border ${hasPendingPhotos ? 'border-emerald-200 dark:border-emerald-900/60 shadow-sm ring-1 ring-emerald-500/10' : 'border-slate-100 dark:border-slate-800'} transition-all">
          <div class="grid grid-cols-1 lg:grid-cols-12 gap-5">
            
            <div class="lg:col-span-7 space-y-2.5 flex flex-col justify-between">
              <div>
                <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div class="flex items-center gap-1.5 text-blue-600 dark:text-blue-400 font-bold">
                    <i data-lucide="calendar" class="w-3.5 h-3.5"></i>
                    <span>${dateFormatted}</span>
                  </div>

                  <div class="flex items-center gap-2">
                    ${note.weather ? `<span class="px-2 py-0.5 rounded-md bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 text-[10px] font-semibold border border-amber-200 dark:border-amber-900/40">🌤️ ${note.weather}</span>` : ''}
                    ${note.location ? `<span class="px-2 py-0.5 rounded-md bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-400 text-[10px] font-semibold border border-indigo-200 dark:border-indigo-900/40">📍 ${note.location}</span>` : ''}
                  </div>
                </div>

                <h3 class="font-bold text-base text-slate-900 dark:text-white mt-1 leading-snug">
                  ${note.title || '<span class="text-slate-400 italic">Senza Titolo</span>'}
                </h3>

                <div class="mt-2 text-xs text-slate-600 dark:text-slate-300 whitespace-pre-wrap font-normal leading-relaxed bg-slate-50 dark:bg-slate-800/40 p-3 rounded-xl border border-slate-100 dark:border-slate-800 max-h-40 overflow-y-auto">
                  ${note.content || '<span class="text-slate-400 italic">Nessun testo presente</span>'}
                </div>
              </div>

              <div class="pt-2 flex items-center justify-between text-xs text-slate-400 border-t border-slate-100 dark:border-slate-800/60">
                <div class="flex items-center gap-2">
                  <span class="text-[11px] font-mono">ID: ${note.id}</span>
                  ${alreadyHasPhotos ? `<span class="text-emerald-600 font-semibold text-[11px]">(${note.photos.length} foto già nel cloud)</span>` : ''}
                </div>
              </div>
            </div>

            <div class="lg:col-span-5 bg-slate-50/50 dark:bg-slate-950/40 p-3 rounded-xl border border-slate-100 dark:border-slate-800/80">
              ${photosHtml}
            </div>

          </div>
        </div>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
  }

  renderOrphanPhotosView(container) {
    if (this.orphanPhotos.length === 0) {
      container.innerHTML = `
        <div class="text-center py-16 text-slate-400">
          <i data-lucide="check-check" class="w-12 h-12 mx-auto mb-2 text-emerald-500"></i>
          <p class="text-sm font-semibold text-slate-700 dark:text-slate-300">Nessuna foto orfana rimasta.</p>
          <p class="text-xs mt-1">Tutte le foto sono state abbinate con successo.</p>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    container.innerHTML = `
      <div class="space-y-4">
        <div class="p-4 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 rounded-xl text-xs text-amber-800 dark:text-amber-300">
          Queste fotografie non sono state abbinate automaticamente a nessuna nota.
          Puoi cliccare su <strong>"Assegna a nota"</strong> per associarle manualmente.
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
          ${this.orphanPhotos.map((photo, idx) => `
            <div class="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm flex flex-col justify-between">
              <div class="aspect-square relative group bg-slate-100 dark:bg-slate-800">
                <img src="${photo.dataUrl}" alt="${photo.name}" class="w-full h-full object-cover cursor-pointer" onclick="importer.openPhotoViewer('${photo.dataUrl}', '${photo.name}')">
                <div class="absolute bottom-0 inset-x-0 bg-black/60 p-1 text-[9px] text-white truncate text-center">
                  ${photo.name}
                </div>
              </div>
              <div class="p-2">
                <button onclick="importer.openAssignModal(${idx})" class="w-full py-1 px-2 bg-blue-50 hover:bg-blue-100 text-blue-600 dark:bg-blue-950/50 dark:hover:bg-blue-900/60 dark:text-blue-300 rounded-lg text-[10px] font-bold transition-all">
                  Assegna a nota
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;

    if (window.lucide) lucide.createIcons();
  }

  // --- AZIONI SULLE FOTO ---
  removePhotoFromNote(noteId, photoIndex) {
    const note = this.firebaseNotes.find(n => n.id === noteId);
    if (!note || !note.pendingPhotos[photoIndex]) return;

    const removedPhoto = note.pendingPhotos.splice(photoIndex, 1)[0];
    this.orphanPhotos.push(removedPhoto);

    this.updateCounters();
    this.renderNotesVerificationList();
    this.showToast('Foto rimossa e spostata in "Foto Orfane"', 'info');
  }

  openAssignModal(orphanIndex) {
    const photo = this.orphanPhotos[orphanIndex];
    if (!photo) return;
    this.activeAssignPhoto = { photo, orphanIndex };

    const modal = document.getElementById('assign-photo-modal');
    const previewImg = document.getElementById('assign-modal-photo-preview');
    const nameEl = document.getElementById('assign-modal-photo-name');
    const dateEl = document.getElementById('assign-modal-photo-date');
    const listEl = document.getElementById('assign-modal-notes-list');

    if (previewImg) previewImg.src = photo.dataUrl;
    if (nameEl) nameEl.textContent = photo.name;
    if (dateEl) dateEl.textContent = photo.dateObj ? formatItalianFull(photo.dateObj) : 'Data sconosciuta';

    if (listEl) {
      listEl.innerHTML = this.firebaseNotes.slice(0, 100).map(n => `
        <div onclick="importer.assignPhotoToNote('${n.id}')" class="p-2.5 rounded-xl border border-slate-100 dark:border-slate-800 hover:border-blue-500 dark:hover:border-blue-500 bg-slate-50 dark:bg-slate-800/40 hover:bg-blue-50/50 dark:hover:bg-blue-950/30 cursor-pointer transition-all flex items-center justify-between gap-3">
          <div class="overflow-hidden">
            <p class="text-xs font-bold text-slate-800 dark:text-slate-200 truncate">${n.title || 'Senza Titolo'}</p>
            <p class="text-[10px] text-slate-400 mt-0.5">${formatItalianFull(n.date)}</p>
          </div>
          <span class="text-[10px] font-bold text-blue-600 shrink-0">Seleziona</span>
        </div>
      `).join('');
    }

    if (modal) modal.classList.remove('hidden');
  }

  closeAssignModal() {
    const modal = document.getElementById('assign-photo-modal');
    if (modal) modal.classList.add('hidden');
    this.activeAssignPhoto = null;
  }

  assignPhotoToNote(noteId) {
    if (!this.activeAssignPhoto) return;
    const note = this.firebaseNotes.find(n => n.id === noteId);
    if (!note) return;

    const { photo, orphanIndex } = this.activeAssignPhoto;
    photo.matchType = 'Assegnata manualmente';
    note.pendingPhotos.push(photo);
    this.orphanPhotos.splice(orphanIndex, 1);

    this.closeAssignModal();
    this.updateCounters();
    this.renderNotesVerificationList();
    this.showToast(`Foto assegnata a "${note.title || 'Nota'}"!`, 'success');
  }

  openPhotoViewer(src, caption) {
    const modal = document.getElementById('photo-viewer-modal');
    const img = document.getElementById('viewer-img');
    const captionEl = document.getElementById('viewer-caption');
    if (img) img.src = src;
    if (captionEl) captionEl.textContent = caption || '';
    if (modal) modal.classList.remove('hidden');
  }

  closePhotoViewer() {
    const modal = document.getElementById('photo-viewer-modal');
    if (modal) modal.classList.add('hidden');
  }

  // --- SALVATAGGIO FIREBASE CLOUD ---
  async saveAllMatchedPhotosToFirebase() {
    const notesToUpdate = this.firebaseNotes.filter(n => n.pendingPhotos.length > 0);
    if (notesToUpdate.length === 0) {
      this.showToast('Nessuna nota ha nuove foto abbinate da salvare.', 'warning');
      return;
    }

    const totalPhotosToUpload = notesToUpdate.reduce((acc, n) => acc + n.pendingPhotos.length, 0);
    const confirmMsg = `Vuoi salvare e memorizzare ${totalPhotosToUpload} fotografie su Firebase Cloud per ${notesToUpdate.length} note?`;
    
    if (!confirm(confirmMsg)) return;

    const modal = document.getElementById('upload-progress-modal');
    const barFill = document.getElementById('progress-bar-fill');
    const countText = document.getElementById('progress-count-text');
    const pctText = document.getElementById('progress-pct-text');
    const modalTitle = document.getElementById('progress-modal-title');
    const modalDesc = document.getElementById('progress-modal-desc');
    const completedActions = document.getElementById('progress-completed-actions');

    if (modal) modal.classList.remove('hidden');
    if (completedActions) completedActions.classList.add('hidden');
    if (modalTitle) modalTitle.textContent = 'Salvataggio su Firebase Cloud...';

    let processed = 0;
    let errorsCount = 0;

    for (let i = 0; i < notesToUpdate.length; i++) {
      const note = notesToUpdate[i];
      try {
        if (modalDesc) modalDesc.textContent = `Salvataggio nota: "${note.title || 'Nota'}" (${i+1}/${notesToUpdate.length})`;

        // Unisci foto esistenti e nuove foto della nota
        const combinedRaw = [...(note.photos || []), ...note.pendingPhotos.map(p => p.dataUrl)];
        const totalCount = combinedRaw.length;

        // Calcola parametri di compressione adattivi in base al numero di foto
        let maxDim = 1200;
        let quality = 0.80;
        if (totalCount > 25) {
          maxDim = 600;
          quality = 0.60;
        } else if (totalCount > 15) {
          maxDim = 720;
          quality = 0.68;
        } else if (totalCount > 8) {
          maxDim = 900;
          quality = 0.74;
        }

        // Prima passata di ottimizzazione
        let finalPhotos = [];
        for (const raw of combinedRaw) {
          const opt = await this.optimizeBase64Image(raw, maxDim, quality);
          finalPhotos.push(opt);
        }

        // Se supera ancora il limite di sicurezza Firestore (~850KB), riduci progressivamente risoluzione/qualità
        let totalSize = finalPhotos.reduce((acc, str) => acc + str.length, 0);
        let retries = 0;
        while (totalSize > 850000 && retries < 3) {
          retries++;
          maxDim = Math.round(maxDim * 0.75);
          quality = Math.max(0.48, quality - 0.10);
          finalPhotos = [];
          for (const raw of combinedRaw) {
            const opt = await this.optimizeBase64Image(raw, maxDim, quality);
            finalPhotos.push(opt);
          }
          totalSize = finalPhotos.reduce((acc, str) => acc + str.length, 0);
        }

        // Salva TUTTE le foto su Firestore tramite REST API
        await this.saveNotePhotosViaRest(note.id, finalPhotos);

        note.photos = finalPhotos;
        note.pendingPhotos = [];
        processed++;
      } catch (saveErr) {
        console.error(`Errore salvataggio nota ${note.id}:`, saveErr);
        errorsCount++;
      }

      const pct = Math.round(((i + 1) / notesToUpdate.length) * 100);
      if (barFill) barFill.style.width = `${pct}%`;
      if (pctText) pctText.textContent = `${pct}%`;
      if (countText) countText.textContent = `${i + 1} / ${notesToUpdate.length} note`;
    }

    if (modalTitle) modalTitle.textContent = 'Salvataggio Completato!';
    if (modalDesc) modalDesc.textContent = `Memorizzate ${totalPhotosToUpload} fotografie su Firebase Cloud!${errorsCount > 0 ? ` (${errorsCount} errori)` : ''}`;
    if (completedActions) completedActions.classList.remove('hidden');

    if (typeof confetti === 'function') {
      confetti({ particleCount: 100, spread: 70, origin: { y: 0.6 } });
    }

    this.updateCounters();
    this.renderNotesVerificationList();
    this.showToast(`Salvate ${processed} note su Firebase Cloud!`, 'success');
  }

  async saveNotePhotosViaRest(noteId, photosArray) {
    const patchUrl = `https://firestore.googleapis.com/v1/projects/${this.projectId}/databases/(default)/documents/notes/${noteId}?updateMask.fieldPaths=photos&updateMask.fieldPaths=updatedAt&key=${this.apiKey}`;
    
    const body = {
      fields: {
        photos: {
          arrayValue: {
            values: photosArray.map(p => ({ stringValue: p }))
          }
        },
        updatedAt: {
          stringValue: new Date().toISOString()
        }
      }
    };

    const response = await fetch(patchUrl, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
  }

  closeProgressModal() {
    const modal = document.getElementById('upload-progress-modal');
    if (modal) modal.classList.add('hidden');
  }

  optimizeBase64Image(dataUrl, maxDimension = 1400, quality = 0.82) {
    return new Promise((resolve) => {
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

        const optimizedUrl = canvas.toDataURL('image/jpeg', quality);
        resolve(optimizedUrl);
      };
      img.onerror = () => resolve(dataUrl);
      img.src = dataUrl;
    });
  }

  fileToDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = err => reject(err);
      reader.readAsDataURL(file);
    });
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    const bgColors = {
      'success': 'bg-emerald-600 text-white',
      'error': 'bg-red-600 text-white',
      'warning': 'bg-amber-600 text-white',
      'info': 'bg-slate-800 text-white'
    };

    toast.className = `${bgColors[type] || bgColors.info} px-4 py-2.5 rounded-xl shadow-lg text-xs font-semibold flex items-center gap-2 transform transition-all duration-300 translate-y-2 opacity-0 pointer-events-auto`;
    toast.innerHTML = `<span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.remove('translate-y-2', 'opacity-0');
    }, 10);

    setTimeout(() => {
      toast.classList.add('opacity-0', 'translate-y-2');
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Inizializzazione
let importer = null;
document.addEventListener('DOMContentLoaded', () => {
  importer = new PhotoImporterApp();
});
