# MASTER PROMPT PER LA RICOSTRUZIONE INTEGRALE DI "MASSINOTE" (v2.19)

> **Istruzioni per l'Agente AI / Sviluppatore**:
> Usa questo prompt per ricreare da zero l'intera WebApp **MassiNote** in tutti i suoi dettagli architetturali, funzionali, grafici e di sicurezza, garantendo il 100% di compatibilità e tutte le funzionalità descritte.

---

```markdown
Sei un Senior Full-Stack Web Engineer esperto in Progressive Web Apps (PWA), Vanilla JavaScript moderno, Tailwind CSS, Web Audio API, IndexedDB e integrazioni di Intelligenza Artificiale multimodale (Google Gemini).

Il tuo obiettivo è creare l'applicazione web completa denominata "MassiNote" (Versione 2.19), un diario e taccuino digitale avanzato, reattivo, completamente funzionante offline e multipiattaforma (Desktop, Smartphone, Tablet).

======================================================================
1. ARCHITETTURA TECNICA & STRUTTURA DEI FILE
======================================================================
L'applicazione deve essere autonoma, senza build tools (no Webpack, Vite, npm):
- `index.html`: Struttura semantica completa, Tailwind CSS v3 via CDN, Lucide Icons via CDN, Canvas Confetti.
- `style.css`: Stili personalizzati, animazioni (fade-in, scale-in, slide-up, shake), textarea auto-espandibile, scrollbar nascoste e gestione dark mode.
- `app.js`: Logica completa ad oggetti (`AppController`, `IndexedDBManager`, `FirebaseStorageManager`), nessun codice parziale o placeholder.
- `manifest.json` & `sw.js`: PWA installabile con cache offline dei file statici.

======================================================================
2. SICUREZZA, VAULT CRITTOGRAFATO & NESSUNA CHIAVE IN CHIARO
======================================================================
- PIN di Accesso predefinito: "1804".
- Calcolo Hash SHA-256: Implementato in puro JavaScript (algoritmo SHA-256 standard) per garantire il funzionamento anche su protocolli locali `file:///` e HTTP non-sicuri (dove `crypto.subtle` fallirebbe).
- Hash memorizzato protetto: `da28719dfd9c4da81f433d4788c3d0e10d97180018d0e32b65c967c45661597e`. Il PIN non deve MAI apparire in chiaro nel codice.
- Vault Crittografato delle Credenziali (`_0xSEC_VAULT` / `_0xSEC_SALT`):
  - NESSUNA chiave API (né Gemini né Firebase) né stringhe di configurazione sensibili devono apparire in chiaro nel codice sorgente.
  - La configurazione Firebase e la chiave Google Gemini AI sono memorizzate in un vault a byte multipli offuscato con scorrimento dinamico.
  - Ricostruzione dinamica in RAM a runtime tramite `_getDecryptedCredentials()`, `getDecryptedGeminiKey()` e `getDecryptedFirebaseConfig()`.
- Timeout Inattività: Blocco automatico dell'app dopo 3 ore di inattività (`10800000 ms`), controllando il timestamp in `localStorage`.
- Protezione con Password su Singola Nota:
  - Tasto Chiave/Lucchetto su ogni card della nota.
  - Se attivato (`note.locked = true`), l'anteprima del testo e le miniature delle foto vengono oscurate.
  - L'apertura della nota o l'esportazione richiede il PIN di sicurezza `1804` (verificato tramite hash crittografico SHA-256 nella modale `#note-pin-modal`).

======================================================================
3. INTEGRAZIONE INTELLIGENZA ARTIFICIALE (GOOGLE GEMINI 3.6 FLASH)
======================================================================
- Endpoint Principale: `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${apiKey}`
- Fallback Automatico: `gemini-3.5-flash` in caso di errore sulla versione 3.6.
- Chiave API Protetta: Decifrata dinamicamente solo in memoria da `getDecryptedGeminiKey()`.
- Input Audio Multimodale: I dati audio sono inviati come `inline_data: { mime_type, data: base64Data }`.
- Prompt di Sistema AI (Note Vocali):
  "Sei un assistente personale intelligente per la gestione degli appunti in italiano. Ascolta attentamente questo file audio registrato dall'utente. Devi generare un JSON valido con: 'title' (titolo conciso max 7-8 parole) e 'summary' (riassunto ordinato e completo scritto come se fosse una nota redatta a mano in italiano)."
- Divieto Sintassi Markdown & Sanitizzazione Automatica:
  - Nei prompt per Gemini è fatto esplicito divieto di usare caratteri Markdown come asterischi `*`, `**`, cancelletti `#`, `##` o trattini bassi `_`.
  - Funzione `cleanAiFormatting(text)`: converte gli elenchi in pallini Unicode `• `, rimuove cancelletti e asterischi di formattazione restituendo testo italiano naturale, pulito e leggibile.
- Ricerca Generativa Intelligente RAG sulle Note (Tasto "AI"):
  - Quando attivato il tasto "AI" sotto la barra di ricerca, invia la domanda dell'utente e il contesto completo di tutte le note dell'archivio a Gemini 3.6 Flash.
  - Restituisce una risposta formulata in italiano pulito (senza `*` né `#`), citando date e luoghi pertinenti, visualizzata in un popup modale (#ai-search-modal).
  - Alla chiusura del popup, il tasto AI torna automaticamente disattivato.
- Monitoraggio Token AI:
  - Estrazione dei token usati dalla risposta (`result.usageMetadata.totalTokenCount` o stima su caratteri).
  - Accumulo e persistenza in `localStorage` (`massinote_ai_tokens_total`, `massinote_ai_audio_count`).
  - Visualizzazione del contatore token cumulativo e delle note vocali analizzate nella schermata Statistiche.

======================================================================
4. REGISTRAZIONE VOCALE, PDF & GALLERIA FOTO A CAROSELLO
======================================================================
- Interazione Hold-to-Record (1,5 Secondi):
  - Tasto "+" centrale mobile ingrandito del +40% (76px con indicatore anulare progress ring a 251px).
  - Se toccato normalmente apre l'editor; se tenuto premuto per 1.5 secondi avvia la registrazione vocale con vibrazione aptica.
  - Nessun suono all'avvio della registrazione; suono armonico discendente di conferma allo stop.
  - Tolleranza al movimento (60px) e cattura tocco (`setPointerCapture`).
  - Durante la registrazione e durante la continuazione con il tasto REC, il tasto in basso scompare completamente lasciando a schermo solo il riquadro centrale con il contatore.
- Esportazione PDF per Singola Nota:
  - Icona PDF rossa su ogni card nota per stampare / scaricare la scheda completa in formato A4 con metadati e immagini.
- Visualizzatore Foto a Carosello & Smart Auto-Rotation:
  - Cliccando su una foto si apre la galleria carosello con tutte le foto della nota.
  - Frecce di navigazione a schermo (`chevron-left`, `chevron-right`), badge posizione ("Foto 2 di 5") e barra miniature inferiore.
  - Supporto gesture Touch Swipe (sinistra/destra) su mobile e frecce da tastiera (`←`, `→`).
  - Smart Auto-Rotation: foto orizzontali ruotano automaticamente di 90° su schermi verticali per sfruttare l'intero display.
  - Tasto "Ruota" manuale (o tasto `R`) per ruotare di 90° e tasto "Ripristina".
- Galleria Foto nell'Editor con Espansione/Compressione (> 4 foto):
  - Se la nota contiene più di 4 fotografie, all'apertura dell'editor vengono mostrate le prime 4 con una freccia e il badge per espandere/comprimere tutte le altre.

======================================================================
5. BACKUP & RIPRISTINO DATI COMPLETO
======================================================================
- Esportazione Backup JSON:
  - Esporta il 100% degli elementi: note, tutte le fotografie (array Base64), registrazioni audio (Base64), stato protezione password (`locked`), meteo, luogo, cartella, etichette e date.
- Ripristino Backup JSON:
  - Importa e normalizza tutte le proprietà memorizzandole in modo persistente in IndexedDB e sincronizzandole su Cloud Firestore.

======================================================================
6. STRUTTURA DELLE VISTE & NAVIGAZIONE
======================================================================
L'app dispone di 5 viste principali commutabili tramite `switchView(viewName)`:
1. **VISTA NOTE (`#view-notes`)**:
   - Barra di ricerca con tasti filtro: "Tutte", "Con Foto", e tasto "AI" per ricerca generativa.
   - Card note con data italiana, badge foto/audio/meteo/luogo/cartella/lucchetto, tasti Condividi, PDF, Chiave e Cestino.
   - Su schermi grandi, il tasto "+ Nuova Nota" è posizionato al centro della barra superiore.
2. **VISTA CALENDARIO (`#view-calendar`)**:
   - Griglia mensile completa, navigazione mese/anno, indicatore note per giorno e visualizzatore note del giorno.
3. **VISTA STATISTICHE (`#view-stats`)**:
   - 6 Card KPI: "Totale note", "Note protette", "Note Audio AI", "Note con foto", "Parole totali", "Località / Meteo".
   - 2 Card Dettaglio: "Spazio Database" (MB) e "Token AI (Audio)".
   - 3 Sezioni Comprimibili: Distribuzione Note per Anno, Località più frequenti, Cartelle & Categorie.
4. **VISTA IMPOSTAZIONI (`#view-settings`)**:
   - Tema chiaro/scuro.
   - Box compatto "Backup & Ripristino Dati" con tasti affiancati "Backup" e "Ripristina".
   - Box "Archiviazione Locale" con contatore a sinistra e tasto "Cancella tutte le note" a destra.
   - Footer finale: "MassiNote WebApp • Versione 2.19".
5. **VISTA EDITOR NOTA (`#view-editor`)**:
   - Header fisso in cima con pulsanti Chiudi, Data/ora, Foto, Salva (blu), Cestino (rosso).
   - Textarea auto-espandibile in altezza (`scrollHeight`, min 250px).
   - Galleria foto con compressione a 4 elementi ed espansione a fisarmonica, audio allegato, meteo e geolocalizzazione automatica.

======================================================================
7. REGOLE DI QUALITÀ & VERSIONAMENTO
======================================================================
- Versione attuale: `2.19`.
- A ogni successiva modifica, incrementare la versione nella costante `APP_VERSION` e nel badge in `index.html`.
- Sanitizzazione completa dei dati (`sanitizeNote`) per prevenire errori su note con campi nulli.
```
