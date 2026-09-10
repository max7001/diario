# MASTER PROMPT PER LA RICOSTRUZIONE INTEGRALE DI "MASSINOTE" (v2.28)

> **Istruzioni per l'Agente AI / Sviluppatore**:
> Usa questo prompt per ricreare da zero l'intera WebApp **MassiNote** in tutti i suoi dettagli architetturali, funzionali, grafici e di sicurezza, garantendo il 100% di compatibilità e tutte le funzionalità descritte.

---

```markdown
Sei un Senior Full-Stack Web Engineer esperto in Progressive Web Apps (PWA), Vanilla JavaScript moderno, Tailwind CSS, Leaflet.js, Web Audio API, IndexedDB e integrazioni di Intelligenza Artificiale multimodale (Google Gemini).

Il tuo obiettivo è creare l'applicazione web completa denominata "MassiNote" (Versione 2.28), un diario e taccuino digitale avanzato, reattivo, completamente funzionante offline e multipiattaforma (Desktop, Smartphone, Tablet).

======================================================================
1. ARCHITETTURA TECNICA & STRUTTURA DEI FILE
======================================================================
L'applicazione deve essere autonoma, senza build tools (no Webpack, Vite, npm):
- `index.html`: Struttura semantica completa, Tailwind CSS v3 via CDN, Leaflet Map CDN, Lucide Icons via CDN, Canvas Confetti.
- `style.css`: Stili personalizzati, animazioni (fade-in, scale-in, slide-up, shake), textarea auto-espandibile, scrollbar nascoste e gestione dark mode.
- `app.js`: Logica completa ad oggetti (`AppController`, `NoteDatabase` con doppio motore IndexedDB/LocalStorage, `FirebaseStorageManager`), nessun codice parziale o placeholder.
- `manifest.json` & `sw.js`: PWA installabile con cache offline dei file statici.

======================================================================
2. SICUREZZA, VAULT CRITTOGRAFATO & AUTENTICAZIONE DISPOSITIVO
======================================================================
- PIN di Accesso predefinito: "1804".
- Calcolo Hash SHA-256: Implementato in puro JavaScript (algoritmo SHA-256 standard) per garantire il funzionamento anche su protocolli locali `file:///` e HTTP non-sicuri.
- Hash memorizzato protetto: `da28719dfd9c4da81f433d4788c3d0e10d97180018d0e32b65c967c45661597e`. Il PIN non deve MAI apparire in chiaro nel codice.
- Memorizzazione Sicura Autenticazione sul Dispositivo:
  - All'inserimento del PIN corretto, viene calcolato e memorizzato in `localStorage` un token crittografato di dispositivo (`massinote_device_auth_token` basato su hash salted `_0xSEC_DEVICE_AUTH_HASH`).
  - Alle riaperture successive dell'app su quel dispositivo, l'accesso avviene istantaneamente e in automatico senza richiedere continuamente il PIN.
  - Nessuna informazione o password in chiaro è accessibile nel codice o nell'archivio locale.
- Vault Crittografato delle Credenziali (`_0xSEC_VAULT` / `_0xSEC_SALT`):
  - NESSUNA chiave API (né Gemini né Firebase) né stringhe di configurazione sensibili in chiaro nel codice.
  - Ricostruzione dinamica in RAM a runtime tramite `_getDecryptedCredentials()`, `getDecryptedGeminiKey()` e `getDecryptedFirebaseConfig()`.
- Protezione con Password su Singola Nota:
  - Tasto Chiave/Lucchetto su ogni card della nota.
  - Se attivato (`note.locked = true`), l'anteprima del testo e le miniature delle foto vengono oscurate.
  - L'apertura della nota o l'esportazione richiede il PIN di sicurezza `1804` (verificato tramite hash crittografico SHA-256 nella modale `#note-pin-modal`).

======================================================================
3. MOTORE DI PERSISTENZA IBRIDO & GESTIONE NOTE "DA LAVORARE" (STELLA)
======================================================================
- Architettura a Doppio Livello:
  - Motore primario su `IndexedDB` (Database `NotesDiaroDB`, Store `notes`) ad alte prestazioni.
  - Motore di fallback trasparente su `LocalStorage` (`massinote_offline_notes_v1`).
- Funzione Stella "Da Lavorare" (In cima alla lista):
  - Tasto Stella nella card nota accanto al tasto Condividi e nell'Editor accanto/sopra al contatore parole.
  - Se attivato (`note.starred = true` / `note.pinned = true`), la stella si illumina in giallo/ambra e la nota viene posta con priorità assoluta **in cima alla lista**.
  - Disattivando la stella, la nota torna all'ordinamento cronologico naturale per data.
- Rendering Non-Bloccante & Sincronizzazione Cloud:
  - All'arrivo dello snapshot da Firestore, l'unione e il rendering visivo a schermo (`render()`) avvengono istantaneamente in memoria, passando allo stato "Sincronizzato".

======================================================================
4. INTEGRAZIONE INTELLIGENZA ARTIFICIALE (GOOGLE GEMINI 3.6 FLASH)
======================================================================
- Endpoint Principale: `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}` (fallback a `gemini-3.5-flash`).
- Input Audio Multimodale: I dati audio sono inviati come `inline_data: { mime_type, data: base64Data }`.
- Prompt di Sistema AI (Note Vocali da Home):
  "Sei un assistente personale intelligente per la gestione degli appunti in italiano. Ascolta attentamente questo file audio registrato dall'utente. Devi generare un JSON valido con: 'title' (titolo conciso max 7-8 parole) e 'summary' (riassunto ordinato e completo scritto come se fosse una nota redatta a mano in italiano)."
- Divieto Sintassi Markdown & Sanitizzazione Automatica:
  - Funzione `cleanAiFormatting(text)`: converte gli elenchi in pallini Unicode `• `, rimuove cancelletti e asterischi di formattazione.
- Ricerca Generativa Intelligente RAG sulle Note (Tasto "AI"):
  - Risponde in italiano pulito formulando risposte contestualizzate alle note salvate.

======================================================================
5. REGISTRAZIONE VOCALE DIFFERENZIATA, MAPPA NOTE, PDF & FOTO
======================================================================
- Registrazione Vocale Differenziata:
  - **Dall'Editor (Tasto Microfono)**: Allo stop, la modale mostra il tasto **"Salva"** (icona disco) per allegare direttamente la traccia audio all'interno della nota corrente senza riassunto AI.
  - **Dalla Home (Hold-to-Record "+")**: Pressione continuata di 1,5 secondi con generazione automatica di nuova nota con IA.
- Mappa Geografica delle Note (Statistiche):
  - Mappa interattiva integrata con Leaflet sotto la sezione "Cartelle & Categorie".
  - Mostra i marcatori di tutte le note che contengono indicazioni di luogo o coordinate geografiche, con popup interattivo contenente titolo, data, località e pulsante rapido per aprire la nota nell'editor.
- Compressione Foto & Galleria a Carosello:
  - Ridimensionamento automatico a max 1080px e compressione JPEG 0.72 (~60-100 KB per foto).
  - Pre-sincronizzazione Cloud (`prepareNoteForCloud` & `compressBase64Image`).
  - Carosello touch-friendly con rotazione automatica e manuale a 90°.
  - Galleria foto comprimibile nell'editor se superiore a 4 foto.
- Esportazione PDF per Singola Nota:
  - Icona PDF su ogni card per esportare/stampare la scheda della nota completa.

======================================================================
6. BACKUP & RIPRISTINO DATI COMPLETO
======================================================================
- Esportazione Backup JSON:
  - Esporta il 100% degli elementi: note, tutte le fotografie (array Base64), registrazioni audio (Base64), stato protezione password (`locked`), stato stella da lavorare (`starred`/`pinned`), meteo, luogo, cartella, etichette e date.
- Ripristino Backup JSON:
  - Importa e normalizza tutte le proprietà memorizzandole in IndexedDB e sincronizzandole su Firestore.

======================================================================
7. STRUTTURA DELLE VISTE & NAVIGAZIONE
======================================================================
L'app dispone di 5 viste principali:
1. **VISTA NOTE (`#view-notes`)**:
   - Layout allargato a `max-w-6xl` allineato all'header.
   - Barra di ricerca con filtri "Tutte", "Con Foto", "AI".
   - Card note con badge (Stella Da Lavorare, Protetta, Vocale, Foto, Meteo, Luogo, Cartella) e pulsanti rapidi (Condividi, Stella, PDF, Chiave, Cestino).
2. **VISTA CALENDARIO (`#view-calendar`)**: Griglia mensile completa e visualizzatore note del giorno.
3. **VISTA STATISTICHE (`#view-stats`)**:
   - 6 Card KPI + 2 Card Dettaglio (Spazio DB, Token AI).
   - 3 Sezioni Comprimibili: Anni, Luoghi, Cartelle.
   - 4a Sezione: **Mappa Geografica delle Note** con marcatori interattivi.
4. **VISTA IMPOSTAZIONI (`#view-settings`)**:
   - Tema chiaro/scuro.
   - Box compatto "Backup & Ripristino Dati" (tasti affiancati Backup e Ripristina).
   - Box "Archiviazione Locale".
   - Footer: "MassiNote WebApp • Versione 2.28".
5. **VISTA EDITOR NOTA (`#view-editor`)**:
   - Header con Chiudi, Data/ora, Microfono (registra e allega), Foto, Salva, Cestino.
   - Toolbar formattazione con: `B` (Grassetto), `-` (Separatore), `Orologio` (Data GG/MM/AA), `Stella` (Da lavorare) e contatore parole.
   - Textarea auto-espandibile, galleria foto ed elementi meteo/geolocalizzazione.

======================================================================
8. REGOLE DI QUALITÀ & VERSIONAMENTO
======================================================================
- Versione attuale: `2.28`.
- A ogni successiva modifica, incrementare la versione nella costante `APP_VERSION` e nel badge in `index.html`.
- Sanitizzazione completa dei dati (`sanitizeNote`) per prevenire errori su note con campi nulli.
```
