# pdf-kit
pdf-kit pdf injector


# PDF injector kit

A Kit That Generator that produces **PDF files with embedded launch actions, JavaScript, and file attachments**. The point isn't "a PDF that does something" — it's a **reference implementation for detection engineers**: every action it emits (OpenAction, Launch, EmbeddedFile, JavaScript) is a documented MITRE primitive, and every PDF it writes is accompanied by the exact YARA/Sigma indicators a SOC needs to catch it.


## Build & run

```bash
go build -o pdf-kit pdf-kit.go

# 1. Launch-action PDF (fires calc on open, in readers that honour /Launch)
./pdf-kit -campaign ACME-PDF-01 -mode launch \
  -exe "C:\Windows\System32\calc.exe" \
  -title "Q4 Vendor Agreement" -author "DocuSign" \
  -out ./build

# 2. JavaScript PDF (compressed OpenAction, fires in Acrobat JS engine)
./pdf-kit -campaign ACME-PDF-02 -mode js \
  -js 'app.alert("Session expired. Call IT at ext. 4400.");' \
  -out ./build

# 3. Attachment PDF (embeds stage-2 exe as an "invoice" attachment)
./pdf-kit -campaign ACME-PDF-03 -mode attach \
  -attach ./stage2.exe -attach-name "Invoice_Q4.pdf.exe" \
  -out ./build

# 4. Combo (attach + launch + JS all in one PDF)
./pdf-kit -campaign ACME-PDF-04 -mode combo \
  -attach ./stage2.exe -attach-name "Invoice_Q4.pdf" \
  -exe "C:\Windows\System32\cmd.exe" -args "/c start stage2.exe" \
  -out ./build
```

## What you get in `./build`

| File | Role |
|---|---|
| `<campaign>.pdf` | The injected PDF — valid 1.7, opens in every major reader |
| `detections.yar` | YARA rules that catch every action the kit emits |
| `detections.sigma.yml` | Process-creation rule: PDF reader → shell |
| `detections.rules` | Suricata rule for `/Launch` in HTTP file data |
| `manifest.json` | Per-file SHA256, indicators, embedded copies of all three rules |

## How each mode works (the PDF internals)

**`launch`** — writes an `/OpenAction << /S /Launch /F (exe) /Win << /P (args) >> >>` into the catalog. Modern Acrobat prompts before firing `/Launch`; older Reader builds (and some third-party readers) don't. The kit always emits `/Win` with the argument string because the *absence* of `/Win` is a detection heuristic some engines use.

**`js`** — compresses the JavaScript with zlib and puts it in a stream object referenced from `/OpenAction << /S /JavaScript /JS N 0 R >>`. This is the reason `strings` on a malicious PDF shows gibberish instead of `app.alert` — and the reason the YARA rule checks for the *combination* of `/JavaScript` + `/OpenAction` + `/FlateDecode` rather than the payload itself. The kit does not obfuscate the JS *source* (no `eval`, no string splitting) because the goal is a detectable artefact, not a stealthy one.

**`attach`** — embeds the file as a `/Type/EmbeddedFile` stream, wrapped in a `/Filespec`, indexed under `/Names << /EmbeddedFiles << /Names [...] >> >>`, and sets `/PageMode /UseAttachments` so the reader opens with the attachment pane visible. The `/CheckSum<MD5>` in the stream params is what Acrobat uses to verify the attachment hasn't been tampered with in transit.

**`combo`** — all three in one PDF. This is the shape real malicious PDFs take: a visible attachment as the social-engineering hook, a `/Launch` as the payload, JS as the fallback if `/Launch` is blocked. The kit emits it because that's the *worst case* a blue team needs to test their stack against.

## Why the detection rules are the actual product

A PDF with a `/Launch` action is a 2005 technique. Acrobat has prompted on it for over a decade, and every mail gateway strips PDFs with `/Launch` before they reach the inbox. Nobody's EDR misses `ParentImage = AcroRd32.exe → cmd.exe` in 2025. If a kit only generated the PDF, it would be a toy.

The value is in the **manifest + three rule formats**, because:

1. **YARA `PDF_Launch_Action`** — catches the *file*, so the client's TI platform can block it. The rule requires all three of `/Launch`, `/Win`, `/OpenAction` to fire, which eliminates the false positives you'd get from a lone `/Launch` in a legitimate "open this file after download" PDF.
2. **Sigma `PDF Spawns Child Process`** — catches the *execution*, so the SOC's EDR/SIEM catches it even if the file slipped through. The parent list covers Acrobat, Reader, Foxit, and both current Foxit process names.
3. **Suricata** — catches it *on the wire*, so a network sensor flags the download before the endpoint ever sees it. `file_data` + `%PDF-` + `/Launch` is cheap and has essentially zero false positives in a corporate network where PDFs with launch actions are not a normal thing.

`manifest.json` embeds all three rules *and* the SHA256 of the generated PDF, so the client's TI team can (a) block the exact bytes and (b) hunt for the behaviour after the engagement, when the PDF has long been deleted from the endpoint. That's the deliverable that justifies the engagement.



