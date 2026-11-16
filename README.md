# 🛡️ Threats Collections - Threat Intelligence Feeds

An automated collection and pipeline engine for Cyber Threat Intelligence (CTI), verified bot validation, and datacenter/cloud detection. This repository aggregates, normalizes, and deduplicates IP reputation feeds, CIDR blocks, Open Proxies, VPN subnets, Tor exit nodes, global ASN directories, and official IP ranges from major search engines and cloud providers directly into clean, ready-to-use flat text files in the `dataset/` directory.

---

## 🌟 Key Features

- **Automated 2-Phase Pipeline (`gets.php`):**
  1. **Phase 1 (Download):** Fetches raw threat intelligence from authoritative sources using streaming cURL with automatic URL fallback mechanisms and custom browser-grade User-Agents into an isolated `temp/` directory.
  2. **Phase 2 (Merge & Deduplicate):** Parses multi-format inputs (JSON, CSV, Netset, Plain Text), strips comments, validates IPv4/CIDR/ASN boundaries, and eliminates duplicates using high-speed in-memory hash indexing. Writes clean, normalized `.txt` files to `dataset/` and cleans up `temp/`.
- **Search Engine Crawler & AI Scraper Validation (Verified Bots):**
  - Includes official IP ranges for Googlebot, Bingbot, OpenAI GPTBot, OpenAI SearchBot, and Applebot to allow white-listing and prevent false positives when crawlers operate from cloud provider IPs.
- **Official Cloud Provider IP Ranges (Anti-Bypass Protection):**
  - Direct integration with official JSON/CSV endpoints from Amazon Web Services (AWS), Cloudflare, DigitalOcean, and Oracle Cloud Infrastructure (OCI) to immediately detect newly spun-up VPS and private VPN exit nodes.
- **Ready for Immediate Integration:**
  - All files in `dataset/` are clean, sorted, flat text files (`.txt`), ready to be consumed directly by **Nginx**, **HAProxy**, **iptables / ipset**, **nftables**, **Fail2ban**, **CrowdSec**, **Suricata**, **Snort**, **MikroTik RouterOS**, or **Cloudflare WAF**.
- **Automated Daily Sync via GitHub Actions:**
  - Runs automatically in the cloud every day at 02:00 UTC (09:00 WIB) without requiring a local server or computer to be on.
- **Targeted Synchronization:**
  - Build all datasets at once or isolate specific categories (e.g., `--feed=bots`, `--feed=dc`, `--feed=vpn`, `--feed=asn_names`).

---

## 📁 Repository Structure

```text
Threats-Collections/
│
├── .github/
│   └── workflows/
│       └── update-feeds.yml     # Automated daily GitHub Actions cron workflow
│
├── dataset/                     # Clean, normalized, deduplicated flat-file datasets
│   ├── vpn.txt                  # Commercial VPN CIDRs (X4BNet + Rocca)
│   ├── datacenter.txt           # Datacenter & Cloud CIDRs (AWS + Cloudflare + DO + OCI + X4BNet + Jhassine)
│   ├── verified_bots.txt        # Official Search Engine & AI Crawler CIDRs (Googlebot, Bingbot, OpenAI, Applebot)
│   ├── firehol_proxies.txt      # Aggregated Open Proxies CIDRs (FireHOL level 1/2/3/4 + xall)
│   ├── ipsum.txt                # Malicious IPs with cumulative threat scores (IPsum)
│   ├── firehol_level2.txt       # Active Attackers CIDRs past 48h (FireHOL Level 2)
│   ├── firehol_level1.txt       # Severe Cybercrime & C2 CIDRs (FireHOL Level 1)
│   ├── spamhaus_drop.txt        # Hijacked networks CIDRs (Spamhaus DROP & EDROP)
│   ├── tor_exit_nodes.txt       # Active Tor Exit Node IPs (SecOps + TorProject)
│   ├── datacenter_asns.txt      # Datacenter, Bad ASN & VPN Autonomous System Numbers
│   └── asn_names.txt            # Global ASN Directory (RIPE NCC + BGP.tools: ASN, Name, Country Code)
│
├── gets.php                     # Pipeline orchestrator and dataset builder (CLI & Web)
├── helpers.php                  # Core helper classes (FileUtils, FeedDownloader, FeedNormalizer, FeedMerger)
├── LICENSE                      # MIT License and Data Disclaimer
├── .gitignore                   # Excludes temporary downloads and local cache
└── README.md                    # Project documentation
```

---

## 📊 Dataset Specifications & Upstream Sources

| Dataset File                      | Upstream Source                                                                                                                                                                                                                                                                                                                                             | Format           | Description / Purpose                                                                                                                       |
| :-------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| **`dataset/vpn.txt`**             | [X4BNet](https://github.com/X4BNet/lists_vpn) & [Joseph Rocca](https://github.com/josephrocca/is-vpn)                                                                                                                                                                                                                                                       | `CIDR`           | Commercial VPN subnets (NordVPN, ExpressVPN, Surfshark, Private Internet Access, etc.)                                                      |
| **`dataset/datacenter.txt`**      | [AWS](https://ip-ranges.amazonaws.com/ip-ranges.json), [Cloudflare](https://www.cloudflare.com/ips-v4), [DigitalOcean](https://digitalocean.com/geo/google.csv), [Oracle OCI](https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json), [X4BNet](https://github.com/X4BNet/lists_vpn), & [Jhassine](https://github.com/jhassine/server-ip-addresses) | `CIDR`           | Official cloud provider IP ranges and VPS hosting subnets (AWS, GCP, Azure, DigitalOcean, Oracle Cloud, Cloudflare CDN, Hetzner, OVH, etc.) |
| **`dataset/verified_bots.txt`**   | [Google Developers](https://developers.google.com/static/search/apis/ipranges/googlebot.json), [Bing Toolbox](https://www.bing.com/toolbox/bingbot.json), [OpenAI](https://openai.com/), & [Apple Developer](https://search.developer.apple.com/applebot.json)                                                                                              | `CIDR\tBOT\tCAT` | Official IPv4 CIDR blocks belonging to legitimate search engine spiders and AI scrapers (Googlebot, Bingbot, GPTBot, SearchBot, Applebot)   |
| **`dataset/firehol_proxies.txt`** | [FireHOL Proxies](https://github.com/firehol/blocklist-ipsets)                                                                                                                                                                                                                                                                                              | `CIDR`           | Aggregation of open HTTP/HTTPS/SOCKS proxies and public web proxies (~2.9M CIDRs)                                                           |
| **`dataset/ipsum.txt`**           | [Stamparm IPsum](https://github.com/stamparm/ipsum)                                                                                                                                                                                                                                                                                                         | `IP\tHITS`       | Actively abusive IPv4 addresses with cumulative blacklist reputation score (1 to 8+)                                                        |
| **`dataset/firehol_level2.txt`**  | [FireHOL Level 2](https://github.com/firehol/blocklist-ipsets)                                                                                                                                                                                                                                                                                              | `CIDR`           | Active attackers tracked over the past 48 hours (DDoS, brute-force scanners, exploit attempts)                                              |
| **`dataset/firehol_level1.txt`**  | [FireHOL Level 1](https://github.com/firehol/blocklist-ipsets)                                                                                                                                                                                                                                                                                              | `CIDR`           | Severe cybercrime, botnet Command & Control (C2), malware hosts, and ransomware operators                                                   |
| **`dataset/spamhaus_drop.txt`**   | [Spamhaus DROP/EDROP](https://www.spamhaus.org/drop/)                                                                                                                                                                                                                                                                                                       | `CIDR`           | Hijacked or maliciously controlled network subnets leased directly to cyber criminals                                                       |
| **`dataset/tor_exit_nodes.txt`**  | [SecOps](https://github.com/SecOps-Institute/Tor-IP-Addresses) & [TorProject](https://check.torproject.org/)                                                                                                                                                                                                                                                | `IP`             | Active exit nodes operating on the Tor anonymity network                                                                                    |
| **`dataset/datacenter_asns.txt`** | [X4BNet](https://github.com/X4BNet/lists_vpn), [Enesutku](https://github.com/enesutku/ASN-List), & [Brian Hama](https://github.com/brianhama/bad-asn-list)                                                                                                                                                                                                  | `ASN\tNAME`      | Autonomous System Numbers associated with datacenter hosting, VPN providers, and malicious networks                                         |
| **`dataset/asn_names.txt`**       | [RIPE NCC](https://ftp.ripe.net/ripe/asnames/asn.txt) & [BGP.tools](https://bgp.tools/asns.csv)                                                                                                                                                                                                                                                             | `ASN\tNAME\tCC`  | Comprehensive worldwide ASN directory containing organization names and ISO country codes (~123,000+ entries)                               |

---

## 🚀 Usage Guide

### 1. System Requirements

- **PHP** 8.0 or higher (PHP 8.1 / 8.2 / 8.3 / 8.4 recommended).
- Required PHP extensions: `curl`, `mbstring`.
- Recommended PHP memory limit (`memory_limit`): `512M` (or `1024M` when processing the complete 49MB FireHOL proxies dataset).

---

### 2. Running via Terminal (CLI)

#### Build All Datasets

Downloads all raw sources and merges/deduplicates them into the `dataset/` directory:

```bash
php gets.php
```

#### Build Specific Dataset Category

Use the `--feed=<name>` argument to process only a targeted dataset:

```bash
# Update Verified Bots only (Googlebot, Bingbot, GPTBot, SearchBot, Applebot)
php gets.php --feed=bots

# Update Datacenter & Cloud Providers only (AWS, Cloudflare, DO, OCI, X4BNet, Jhassine)
php gets.php --feed=dc

# Update Commercial VPN ranges only
php gets.php --feed=vpn

# Update Tor Exit Nodes only
php gets.php --feed=tor

# Update IPsum Threat scores only
php gets.php --feed=ipsum

# Update Threat ASN Rules (Datacenter, Bad ASN & VPN) only
php gets.php --feed=asn

# Update Global ASN Directory (RIPE NCC / BGP.tools) only
php gets.php --feed=asn_names

# Update FireHOL Level 1 (Malware) only
php gets.php --feed=firehol1

# Update FireHOL Level 2 (Attackers) only
php gets.php --feed=firehol2

# Update Spamhaus DROP only
php gets.php --feed=spamhaus

# Update FireHOL Aggregated Proxies only (~49MB, ~2.9M CIDRs)
php gets.php --feed=proxies
```

---

### 3. Running via Web Browser

Access the script using a local web server (Laragon, Apache, Nginx) or PHP's built-in server:

```bash
# Start PHP built-in server on port 8000
php -S 127.0.0.1:8000
```

Open your browser to:

- **Build All Datasets:** `http://localhost:8000/gets.php`
- **Build Verified Bots:** `http://localhost:8000/gets.php?feed=bots`
- **Build Cloud & Datacenter:** `http://localhost:8000/gets.php?feed=dc`

The browser interface streams real-time console logs with auto-scroll.

---

## ⚙️ Automation & Keeping Datasets Up-to-Date

### 1. GitHub Actions (Automated Cloud Sync - Recommended)

This repository includes a ready-to-use GitHub Actions workflow in [`.github/workflows/update-feeds.yml`](.github/workflows/update-feeds.yml).

- **Runs completely serverless** inside GitHub's free runners (no local computer/server required).
- Scheduled to run **daily at 02:00 UTC (09:00 WIB)**.
- Can also be triggered manually anytime via the **Actions** tab on GitHub (`workflow_dispatch`).
- If any upstream data changes, the workflow automatically commits and pushes the updated `.txt` files in `dataset/` back to your repository.

To enable it, ensure your GitHub repository has write permissions enabled for GitHub Actions:

> **Repository Settings** $\rightarrow$ **Actions** $\rightarrow$ **General** $\rightarrow$ **Workflow permissions** $\rightarrow$ Select **"Read and write permissions"** $\rightarrow$ Click **Save**.

### 2. Linux Cron Job (Self-Hosted Server)

If you run the builder on your own Linux server or VPS:

Run full daily synchronization at 02:00 AM:

```cron
0 2 * * * /usr/bin/php /path/to/Threats-Collections/gets.php >> /var/log/threat-feeds.log 2>&1
```

Update Tor Exit Nodes every 2 hours:

```cron
0 */2 * * * /usr/bin/php /path/to/Threats-Collections/gets.php --feed=tor >> /var/log/tor-sync.log 2>&1
```

---

## 🛡️ Production Usage Examples

### 1. Nginx IP Blocking

Include CIDR files directly inside your Nginx configuration:

```nginx
# Map client IP to blocked status
geo $is_blocked {
    default         0;
    include         /path/to/Threats-Collections/dataset/firehol_level1.txt;
    include         /path/to/Threats-Collections/dataset/spamhaus_drop.txt;
}

server {
    listen 80;
    server_name example.com;

    if ($is_blocked) {
        return 403 "Access Denied by Threat Intelligence Policy";
    }
}
```

### 2. Linux iptables / ipset

Block severe threats with zero CPU overhead using `ipset`:

```bash
# Create ipset hash set for networks
ipset create threat_blocklist hash:net

# Populate from FireHOL Level 1
while read cidr; do
    ipset add threat_blocklist "$cidr" -exist
done < /path/to/Threats-Collections/dataset/firehol_level1.txt

# Drop incoming packets in iptables
iptables -I INPUT -m set --match-set threat_blocklist src -j DROP
```

---

## 📜 License & Attribution

This project and its pipeline code are licensed under the [MIT License](LICENSE).

This project is created strictly for cybersecurity research, fraud prevention, and malicious traffic mitigation. All raw intelligence feeds originate from open-source security communities and official provider APIs:

- [Google Search Central Official IP Ranges](https://developers.google.com/search/docs/crawling-indexing/googlebot-ip-ranges)
- [Microsoft Bingbot IP Ranges](https://www.bing.com/toolbox/bingbot.json)
- [OpenAI Crawlers (GPTBot & SearchBot)](https://platform.openai.com/docs/bots)
- [Applebot Official IP Ranges](https://support.apple.com/en-us/HT204683)
- [Amazon Web Services (AWS) IP Ranges](https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html)
- [Cloudflare Official IPv4/IPv6 CIDRs](https://www.cloudflare.com/ips/)
- [DigitalOcean Geolocation IP Ranges](https://www.digitalocean.com/)
- [Oracle Cloud Infrastructure (OCI) IP Ranges](https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json)
- [RIPE NCC Official ASN Names](https://ftp.ripe.net/ripe/asnames/)
- [BGP.tools Research Platform](https://bgp.tools/)
- [FireHOL IP Lists](https://iplists.firehol.org/)
- [The Spamhaus Project](https://www.spamhaus.org/)
- [The Tor Project](https://check.torproject.org/)
- [IPsum by Stamparm](https://github.com/stamparm/ipsum)
- [X4BNet Threat Feeds](https://github.com/X4BNet)
- [Joseph Rocca](https://github.com/josephrocca/is-vpn)
- [Jhassine Datacenter IPs](https://github.com/jhassine/server-ip-addresses)
- [Enesutku ASN-List](https://github.com/enesutku/ASN-List)
- [Brian Hama Bad ASN List](https://github.com/brianhama/bad-asn-list)
