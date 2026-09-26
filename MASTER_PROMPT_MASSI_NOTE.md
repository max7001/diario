# MASTER PROMPT PER LA RICOSTRUZIONE INTEGRALE DI "MASSINOTE" (v2.35)

> **Istruzioni per l'Agente AI / Sviluppatore**:
> Usa questo prompt per ricreare da zero l'intera WebApp **MassiNote** in tutti i suoi dettagli architetturali, funzionali, grafici e di sicurezza, garantendo il 100% di compatibilità e parità assoluta con la versione Android (APK Diario) e tutte le funzionalità descritte.

---

```markdown
Sei un Senior Full-Stack Web Engineer esperto in Progressive Web Apps (PWA), Vanilla JavaScript moderno, Tailwind CSS, Leaflet.js, Web Audio API, IndexedDB e integrazioni di Intelligenza Artificiale multimodale (Google Gemini).

Il tuo obiettivo è creare l'applicazione web completa denominata "MassiNote" (Versione 2.35), un diario e taccuino digitale avanzato, reattivo, completamente funzionante offline e multipiattaforma (Desktop, Smartphone, Tablet), trasposizione esatta e sincronizzata della versione nativa Android.

======================================================================
1. ARCHITETTURA TECNICA & STRUTTURA DEI FILE
======================================================================
L'applicazione deve essere autonoma, senza build tools (no Webpack, Vite, npm):
- `index.html`: Struttura semantica completa, Tailwind CSS v3 via CDN, Leaflet Map CDN, Lucide Icons via CDN, Canvas Confetti.
- `style.css`: Stili personalizzati, animazioni (fade-in, scale-in, slide-up, shake), textarea auto-espandibile, scrollbar nascoste e gestione dark mode.
- `app.js`: Logica completa ad oggetti (`AppController`, `NoteDatabase` con doppio motore IndexedDB/LocalStorage, `FirebaseStorageManager`), nessun codice parziale o placeholder.
- `manifest.json` & `sw.js`: PWA installabile con cache offline dei file statici.

======================================================================
2. SICUREZZA, VAULT CRITTOGRAFATO & AUTENTICAZIONE DISPOSITIVO (60 GIORNI)
======================================================================
- PIN di Accesso predefinito: "1804".
- Calcolo Hash SHA-256: Implementato in puro JavaScript (algoritmo SHA-256 standard) per garantire il funzionamento anche su protocolli locali `file:///` e HTTP non-sicuri.
- Hash memorizzato protetto: `da28719dfd9c4da81f433d4788c3d0e10d97180018d0e32b65c967c45661597e`. Il PIN non deve MAI apparire in chiaro nel codice.
- Memorizzazione Sicura Autenticazione sul Dispositivo (60 Giorni):
  - All'inserimento del PIN corretto, viene calcolato e memorizzato in `localStorage` un token crittografato di dispositivo (`massinote_device_auth_token` basato su hash salted `_0xSEC_DEVICE_AUTH_HASH`) con timestamp di scadenza a 60 giorni (`massinote_auth_expires_at`).
  - Alle riaperture successive dell'app su quel dispositivo (o ritorno dal background con `visibilitychange`), l'accesso avviene istantaneamente e in automatico senza richiedere continuamente il PIN, con schermo di sblocco inizialmente nascosto (`hidden`) per prevenire sfarfallii.
- Vault Crittografato delle Credenziali (`_0xSEC_VAULT` / `_0xSEC_SALT`):
  - NESSUNA chiave API (né Gemini né Firebase) né stringhe di configurazione sensibili in chiaro nel codice.
  - Ricostruzione dinamica in RAM a runtime tramite `_getDecryptedCredentials()`, `getDecryptedGeminiKey()` e `getDecryptedFirebaseConfig()`.
- Protezione con Password su Singola Nota:
  - Tasto Chiave/Lucchetto su ogni card della nota.
  - Se attivato (`note.locked = true`), l'anteprima del testo e le miniature delle foto vengono oscurate.
  - L'apertura della nota o l'esportazione richiede il PIN di sicurezza `1804` (verificato tramite hash crittografico SHA-256 nella modale `#note-pin-modal`).

======================================================================
3. MOTORE DI PERSISTENZA IBRIDO, TRACCIAMENTO CANCELLAZIONI & RISINCRONIZZAZIONE CLOUD
======================================================================
- Architettura a Doppio Livello con Tracciamento Delezioni:
  - Motore primario su `IndexedDB` (Database `NotesDiaroDB`, Store `notes`) ad alte prestazioni.
  - Motore di fallback trasparente su `LocalStorage` (`massinote_offline_notes_v1`).
  - Registro Delezioni Persistente (`massinote_deleted_ids` in localStorage): `getDeletedNoteIds()`, `addDeletedNoteId()`, `removeDeletedNoteId()`, `flushPendingDeletions()` per riconciliare bidirezionalmente le eliminazioni tra dispositivi diversi (WebApp e Android APK).
- Sincronizzazione Automatica alla Riconnessione:
  - Listener `window.addEventListener('online', ...)` che avvia automaticamente il download e l'unione dei dati dal Cloud non appena la rete torna disponibile.
- Tasto / Badge "Sincronizzato" Cliccabile (Risincronizzazione Manuale):
  - Posizionato accanto al titolo nell'header superiore (`#cloud-status-badge`).
  - Cliccandolo, avvia una risincronizzazione autoritativa con il database Firebase Firestore (`fetchLatestNotes()`), ripulisce la coda delezioni pendenti, allinea istantaneamente tutte le note e cancella dal database locale IndexedDB le note eliminate da altri dispositivi.
- Funzione Stella "Da Lavorare" & Layout Card Compatto:
  - **Barra Superiore**: Tasto Filtro Stella accanto al tasto AI nella barra di ricerca per mostrare solo le note con la stella attiva.
  - **Card Nota Compatta**: Le note contrassegnate con la stella ("Da Lavorare") vengono mostrate in cima alla lista con layout compatto (padding ridotto `p-3 sm:p-3.5`, senza anteprima di testo e meteo per ottimizzare lo spazio visivo verticale).
  - **Editor Nota**: Tasto Stella posizionato nella toolbar di formattazione.
- Filtro a Tendina "Categoria" & Esportazione PDF Categoria:
  - Posizionato sotto la barra di ricerca nella schermata principale, ordinato per data di creazione più recente in alto con conteggio note.
  - Tasto PDF dedicato per la categoria selezionata: genera un PDF multi-pagina (1 nota per pagina, foto formattate a 3 per riga).
- Cartella Fissa / Clessidra nell'Editor:
  - Tasto Clessidra (`data-lucide="hourglass"`) accanto al campo "Cartella / Categoria" nell'editor per applicare automaticamente la cartella a tutte le note successive.
- Protezione Anti-Click / Debounce Tasto "+" e Banner Registrazione:
  - Blocco di sicurezza da 900ms-1000ms (`_ignoreClickUntil` e `lastVoiceRecordingEndTime`) per prevenire aperture o tocchi accidentali di note sottostanti allo stop della registrazione vocale.

======================================================================
4. STRUMENTI INTELLIGENZA ARTIFICIALE GEMINI (GEMINI 3.6 FLASH)
======================================================================
- Modello Principale: `gemini-3.6-flash:generateContent?key=${apiKey}` (con fallback automatico a `gemini-3.5-flash`).
- Strumenti AI Integrati:
  1. **AI Riorganizza Testo nell'Editor (`reorganizeNoteTextWithAi()`)**:
     - Pulsante dedicato `#editor-ai-rewrite-btn` (icona `sparkles` con testo `AI`) posizionato accanto al campo Titolo nell'Editor.
     - Analizza, corregge ortografia e sintassi, struttura ed evidenzia i punti salienti del testo della nota mantenendo intatto il significato originario.
  2. **AI Riassumi Audio Registrato nell'Editor (`summarizeEditorAudioWithAi()`)**:
     - Pulsante dedicato `#editor-audio-ai-btn` nell'intestazione del player audio dell'Editor.
     - Analizza e trascrive/riassume la traccia vocale allegata alla nota inserendola direttamente nel corpo del testo.
  3. **AI Riassunto Vocale Hold-to-Record dalla Home**:
     - Pressione prolungata (1.2s) del tasto "+" per creare al volo una nuova nota completa di titolo sintetico e riassunto ordinato.
  4. **AI Ricerca RAG Intelligente sulle Note**:
     - Pulsante "AI" accanto alla barra di ricerca nella home per dialogare e cercare contestualmente tra tutte le note salvate.
- Divieto Sintassi Markdown & Sanitizzazione Automatica:
  - Funzione `cleanAiFormatting(text)`: converte gli elenchi in pallini Unicode `• `, rimuove cancelletti `#` e asterischi di formattazione `*`.
- Tracciamento Token Utilizzati (`massinote_ai_tokens_usage`).

======================================================================
5. REGISTRAZIONE VOCALE, MAPPA NOTE, PDF & FOTO
======================================================================
- Registrazione Vocale:
  - Banner a schermo intero con blocco propagazione eventi touch (`stopVoiceRecording(e)` con `stopPropagation()` e `stopImmediatePropagation()`).
  - Dall'Editor (Tasto Microfono): tasto "Salva" (icona disco) per allegare direttamente la traccia audio alla nota senza passare da AI.
- Mappa Geografica delle Note (Statistiche):
  - Mappa interattiva integrata con Leaflet sotto la sezione "Cartelle & Categorie", con badge compatto ("0 Punti").
- Compressione Foto & Galleria:
  - Compressione JPEG 0.72 (~60-100 KB) con pre-ottimizzazione per Firestore (`prepareNoteForCloud` & `compressBase64Image`).
  - Carosello touch-friendly con rotazione manuale a 90°.
- Esportazione PDF Completa:
  - Tasto PDF nella toolbar di formattazione dell'Editor, su ogni card nota e nel filtro Categoria.

======================================================================
6. BACKUP & RIPRISTINO DATI COMPLETO
======================================================================
- Esportazione Backup JSON:
  - Esporta il 100% degli elementi: note, fotografie (array Base64), registrazioni audio, stato password (`locked`), stella (`starred`), meteo, luogo, cartelle e date.
- Ripristino Backup JSON:
  - Importa e normalizza tutte le proprietà in IndexedDB e sincronizza su Firestore.

======================================================================
7. STRUTTURA DELLE VISTE & NAVIGAZIONE
======================================================================
5 viste principali:
1. **VISTA NOTE (`#view-notes`)**: Barra di ricerca a riga unica con tasti AI e Filtro Stella, tendina Categorie con tasto PDF, card note compatte per note da lavorare.
2. **VISTA CALENDARIO (`#view-calendar`)**: Griglia mensile con indicatore note del giorno.
3. **VISTA STATISTICHE (`#view-stats`)**: KPI, spazio occupato, token AI, sezioni comprimibili e mappa geografica interattiva.
4. **VISTA IMPOSTAZIONI (`#view-settings`)**: Card Tema Giorno/Notte compatta, Backup, Ripristino, Eliminazione totale, Badge Versione 2.35.
5. **VISTA EDITOR NOTA (`#view-editor`)**: Tasto Salva, Annulla, Allega Foto, Registra Voce, Tasto AI Riorganizza Testo, Tasto AI Riassumi Audio, Toolbar formattazione (B, -, Orologio, PDF, Stella), Clessidra Cartella Fissa.
```
