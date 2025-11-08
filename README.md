# Project Description

## SiteScanner — Command-Line Website Safety Scanner

**SiteScanner** is a lightweight yet powerful **command-line website safety scanner** designed to evaluate the **security, integrity, and trustworthiness** of websites using heuristic analysis and modern security checks.

The tool automatically inspects a target URL and performs multiple layers of analysis — including **HTML structure**, **HTTP headers**, **SSL/TLS certificates**, and **domain reputation** — to identify potential signs of **phishing**, **malware**, or **misconfigurations** that could compromise user safety.

---

## Features

- **Heuristic HTML Analysis** — Detects suspicious scripts, inline code, iframes, and hidden payloads.  
- **Security Header Check** — Verifies essential headers such as `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Frame-Options`.  
- **SSL/TLS Validation** — Checks for expired, invalid, or missing certificates.  
- **Domain Intelligence** — Gathers WHOIS information and evaluates domain age for reputation scoring.  
- **External API Integration (Optional)** — Supports **VirusTotal** and **Google Safe Browsing** lookups.  
- **Rich Terminal Interface** — Displays detailed results in a structured and colorized format using the [Rich](https://github.com/Textualize/rich) library.  
- **JSON Report Export** — Exports full scan reports for automation or audit use.  

---

## Usage

```bash
python scanner.py https://example.com
````

**Optional (with API keys):**

```bash
python scanner.py https://example.com --vt-key YOUR_VT_API_KEY --gsb-key YOUR_GSB_API_KEY --export-json report.json
```

---

## Example Output

* Verdicts: **SAFE**, **SUSPICIOUS**, or **UNSAFE**
* Displays risk score, missing headers, SSL issues, and page summary
* Clean, readable CLI report with color-coded severity indicators

---

## Tech Stack

* **Python 3**
* **Rich**
* **BeautifulSoup4**
* **requests**
* **tldextract**
* **whois**

---

## License

Open-source under the **MIT License** — contributions and improvements are welcome.

```
```
