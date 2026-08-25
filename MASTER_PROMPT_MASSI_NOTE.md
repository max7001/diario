# MASTER PROMPT PER LA RICOSTRUZIONE INTEGRALE DI "MASSINOTE" (v2.16)

> **Istruzioni per l'Agente AI / Sviluppatore**:
> Usa questo prompt per ricreare da zero l'intera WebApp **MassiNote** in tutti i suoi dettagli architetturali, funzionali, grafici e di sicurezza, garantendo il 100% di compatibilità e tutte le funzionalità descritte.

---

```markdown
Sei un Senior Full-Stack Web Engineer esperto in Progressive Web Apps (PWA), Vanilla JavaScript moderno, Tailwind CSS, Web Audio API, IndexedDB e integrazioni di Intelligenza Artificiale multimodale (Google Gemini).

Il tuo obiettivo è creare l'applicazione web completa denominata "MassiNote" (Versione 2.16), un diario e taccuino digitale avanzato, reattivo, completamente funzionante offline e multipiattaforma (Desktop, Smartphone, Tablet).

======================================================================
1. ARCHITETTURA TECNICA & STRUTTURA DEI FILE
======================================================================
L'applicazione deve essere autonoma, senza build tools (no Webpack, Vite, npm):
- `index.html`: Struttura semantica completa, Tailwind CSS v3 via CDN, Lucide Icons via CDN, Canvas Confetti.
- `style.css`: Stili personalizzati, animazioni (fade-in, scale-in, slide-up), textarea auto-espandibile, scrollbar nascoste e gestione dark mode.
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
- Schermata di Sblocco (#lock-screen): 
  - Design pulito ed elegante con icona lucchetto e campo PIN centrale con focus automatico.
  - Nessun tastierino a 12 bottoni a schermo: l'utente digita direttamente dalla tastiera fisica o virtuale del dispositivo.
  - Sblocco istantaneo alla digitazione della quarta cifra corretta o alla pressione di Invio (nessun tasto "Sblocca").
  - Animazione shake e messaggio rosso in caso di PIN errato.

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
4. REGISTRAZIONE VOCALE & CONTINUAZIONE REC TRAMITE RIQUADRO CENTRALE
======================================================================
- Interazione Hold-to-Record (~2 Secondi):
  - Tasto "+" centrale (FAB mobile o desktop): se premuto normalmente apre l'editor; se tenuto premuto per ~2 secondi (con indicatore SVG progress ring) avvia la registrazione vocale e fa vibrare il dispositivo.
  - Al rilascio del tasto, la registrazione si interrompe istantaneamente e apre la finestra di revisione con 3 tasti (Cestino, REC, Salva IA).
- Continuazione della Registrazione (Tasto REC):
  - Nella finestra di revisione è presente il tasto "REC". Cliccandolo la registrazione riprende, concatenando automaticamente i blocchi audio registrati.
  - Non si apre alcuna nota e la tastiera virtuale mobile rimane completamente chiusa.
  - Lo schermo mostra unicamente il riquadro centrale nero/rosso con il contatore (tempo cumulativo).
  - **Tocco del Riquadro Centrale**: Toccando direttamente il riquadro al centro dello schermo, la registrazione si ferma e torna al popup dei 3 tasti (nessun pulsante extra ridondante in basso).
- Elaborazione e Apertura Nota su "Salva (IA)":
  - Premendo "Salva (IA)", l'audio completo combinato viene inviato a Gemini per l'analisi.
  - Al termine dell'analisi, viene creata la nota e aperta direttamente nell'editor con titolo e testo compilati per la consultazione o modifica.
- Segnali Acustici Web Audio API (Senza dipendenze esterne):
  - Avvio Registrazione / Ripresa: doppio tono armonico ascendente chiaro (`520Hz -> 880Hz`).
  - Termine Registrazione: tono discendente morbido di conferma (`880Hz -> 440Hz`).

======================================================================
5. STRUTTURA DELLE VISTE & NAVIGAZIONE
======================================================================
L'app dispone di 5 viste principali commutabili tramite `switchView(viewName)`:
1. **VISTA NOTE (`#view-notes`)**:
   - Barra di ricerca con tasti filtro: "Tutte", "Con Foto", e tasto "AI" per ricerca generativa.
   - Vista a griglia responsiva o compatta con badge foto, meteo, luogo, audio e date italiane formattate.
2. **VISTA CALENDARIO (`#view-calendar`)**:
   - Griglia mensile completa, navigazione mese/anno, indicatore note per giorno e visualizzatore note del giorno.
3. **VISTA STATISTICHE (`#view-stats`)**:
   - 4 Card KPI (Totale Note, Note con Foto, Parole Totali, Località/Meteo).
   - 2 Card Dettaglio: "Spazio Database" (MB) e "Token AI (Audio)".
   - 3 Sezioni Comprimibili con freccia e badge (Distribuzione Note per Anno, Località più frequenti, Cartelle & Categorie).
4. **VISTA IMPOSTAZIONI (`#view-settings`)**:
   - Tema chiaro/scuro, Backup/Restore JSON, Archiviazione locale e cancellazione sicura note.
   - Footer finale: "MassiNote WebApp • Versione 2.16".
5. **VISTA EDITOR NOTA (`#view-editor`)**:
   - Header fisso in cima con pulsanti Chiudi, Data/ora, Foto, Salva (blu), Cestino (rosso).
   - Textarea auto-espandibile in altezza (`scrollHeight`, min 250px).
   - Foto multiple con visualizzatore fullscreen, audio allegato, meteo e geolocalizzazione automatica.

======================================================================
6. REGOLE DI QUALITÀ & VERSIONAMENTO
======================================================================
- Versione attuale: `2.16`.
- A ogni successiva modifica, incrementare la versione nella costante `APP_VERSION` e nel badge in `index.html`.
- Sanitizzazione completa dei dati (`sanitizeNote`) per prevenire errori su note con campi nulli.
- Toast feedback non bloccante per ogni azione dell'utente.
```
