# 🛡️ AegisAPI — Automated API Vulnerability Scanner 
AegisAPI is a **single-file Python tool** that performs passive + active reconnaissance, vulnerability testing, and Shodan enrichment against one domain, then writes an HTML report.

## 🔥 Features
- Passive recon via Google Dorks
- Active recon with `gau`, `waybackurls`
- Vulnerability tests: LFI, RFI, XSS, SQLi, Open Redirect
- Shodan integration (ports, services, OS)
- Bootstrap-styled HTML report

## ⚙️ Prerequisites
1. Python 3.8+ & pip 
```bash
python3 -m pip install -r requirements.txt
```
2. Go-based tools 
```bash
# install Go first: https://go.dev/dl/
go install github.com/lc/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
# ensure ~/go/bin is in %%PATH%%
```

## 🚀 Usage
1. Clone repo  
2. Install deps  
3. Run scan  
```bash
python3 aegisapi.py example.com YOUR_SHODAN_API_KEY
```
4. View report  
Open `aegis_results/aegis_report.html` in any browser.

## 📂 Outputs
- `aegis_results/aegis_report.html` 
- passive_urls.txt 
- active_urls.txt 
- endpoints.txt

## ⚖️ Legal & Ethical
- Only scan targets you own or have explicit permission to test.
- AegisAPI is for educational & authorized security testing only.
