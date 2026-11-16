<?php
/**
 * Threats Collections - Threat Feeds Collector & Dataset Builder
 *
 * 2-Phase Resilient Pipeline (Flat-File Edition):
 * 1. DOWNLOAD PHASE: Downloads all raw datasets into the isolated "temp/" directory.
 * 2. MERGE & DEDUPLICATION PHASE: Extracts, normalizes formats, eliminates duplicates,
 *    and writes clean, standard .txt dataset files to the "dataset/" directory.
 *    The "temp/" directory is automatically cleaned up afterwards.
 *
 * Generated Artifacts in "dataset/":
 * - dataset/vpn.txt              (Merged X4BNet VPN + Joseph Rocca VPN)
 * - dataset/datacenter.txt       (Merged X4BNet DC + Jhassine + AWS + Cloudflare + DigitalOcean + Oracle Cloud)
 * - dataset/verified_bots.txt    (Official Bots: Googlebot, Bingbot, GPTBot, SearchBot, Applebot: CIDR\tName\tCategory)
 * - dataset/tor_exit_nodes.txt   (Merged SecOps Tor + TorProject Bulk Exit List)
 * - dataset/ipsum.txt            (IPsum Threat Feed: IP\tHits)
 * - dataset/firehol_level1.txt   (FireHOL Level 1 Malware Threat CIDR)
 * - dataset/firehol_level2.txt   (FireHOL Level 2 Active Attackers CIDR)
 * - dataset/firehol_proxies.txt  (FireHOL Aggregated Open Proxies CIDR)
 * - dataset/spamhaus_drop.txt    (Spamhaus DROP Hijacked Nets CIDR)
 * - dataset/datacenter_asns.txt  (Merged X4BNet DC + X4BNet VPN + Enesutku + Brian Hama Bad ASN: ASN\tName)
 * - dataset/asn_names.txt        (Global ASN Directory: RIPE NCC + BGP.tools: ASN\tName\tCC)
 *
 * Execution Options:
 * - php gets.php                   (Collect and build all datasets)
 * - php gets.php --feed=<name>     (Filter: vpn, dc, bots, tor, ipsum, firehol, asn, asn_names, spamhaus)
 */

require_once __DIR__ . "/helpers.php";

// Increase execution time and memory limits for massive datasets
set_time_limit(1800);
ini_set("memory_limit", "512M");

// CLI vs Browser rendering
$isCli = php_sapi_name() === "cli";
if (!$isCli) {
    header("Content-Type: text/plain; charset=utf-8");
    @ini_set("zlib.output_compression", "0");
    @ini_set("implicit_flush", "1");
    for ($i = 0; $i < ob_get_level(); $i++) {
        ob_end_flush();
    }
    ob_implicit_flush(1);
}

function logger(string $message): void
{
    $time = date("Y-m-d H:i:s");
    echo "[{$time}] {$message}\n";
    @flush();
}

class ThreatDatasetBuilder
{
    private string $tempDir;
    private string $datasetDir;

    public function __construct(string $tempDir, string $datasetDir)
    {
        $this->tempDir = $tempDir;
        $this->datasetDir = $datasetDir;

        FileUtils::ensureDir($this->tempDir);
        FileUtils::ensureDir($this->datasetDir);
    }

    // -------------------------------------------------------------
    // PHASE 1: DOWNLOAD RAW SOURCES TO TEMP
    // -------------------------------------------------------------

    public function downloadRawSources(?string $target = null): void
    {
        logger("--- [PHASE 1] DOWNLOADING RAW DATASETS TO TEMP/ DIRECTORY ---");

        $tasks = [
            // 1. VPN
            "vpn" => [
                [
                    "name" => "X4BNet VPN",
                    "url" =>
                        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
                    "file" => $this->tempDir . "/x4bnet_vpn.txt",
                ],
                [
                    "name" => "Joseph Rocca VPN",
                    "url" =>
                        "https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv4-ranges.txt",
                    "file" => $this->tempDir . "/josephrocca_vpn.txt",
                ],
            ],
            // 2. Datacenter & Official Cloud Providers
            "dc" => [
                [
                    "name" => "X4BNet Datacenter",
                    "url" =>
                        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt",
                    "file" => $this->tempDir . "/x4bnet_dc.txt",
                ],
                [
                    "name" => "Jhassine Datacenters",
                    "url" =>
                        "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.txt",
                    "file" => $this->tempDir . "/jhassine_dc.txt",
                ],
                [
                    "name" => "AWS Official IP Ranges",
                    "url" => "https://ip-ranges.amazonaws.com/ip-ranges.json",
                    "file" => $this->tempDir . "/aws_ip_ranges.json",
                ],
                [
                    "name" => "Cloudflare Official IPv4",
                    "url" => "https://www.cloudflare.com/ips-v4",
                    "file" => $this->tempDir . "/cloudflare_v4.txt",
                ],
                [
                    "name" => "DigitalOcean Geo Ranges",
                    "url" => "https://digitalocean.com/geo/google.csv",
                    "file" => $this->tempDir . "/digitalocean.csv",
                ],
                [
                    "name" => "Oracle Cloud (OCI) Public IP Ranges",
                    "url" =>
                        "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
                    "file" => $this->tempDir . "/oracle_cloud.json",
                ],
            ],
            // 3. Search Engine Crawlers & AI Scrapers (Verified Bots)
            "bots" => [
                [
                    "name" => "Googlebot Official IP Ranges",
                    "url" =>
                        "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
                    "file" => $this->tempDir . "/bot_google.json",
                ],
                [
                    "name" => "Bingbot Official IP Ranges",
                    "url" => "https://www.bing.com/toolbox/bingbot.json",
                    "file" => $this->tempDir . "/bot_bing.json",
                ],
                [
                    "name" => "OpenAI GPTBot IP Ranges",
                    "url" => "https://openai.com/gptbot.json",
                    "file" => $this->tempDir . "/bot_gpt.json",
                ],
                [
                    "name" => "OpenAI SearchBot IP Ranges",
                    "url" => "https://openai.com/searchbot.json",
                    "file" => $this->tempDir . "/bot_searchbot.json",
                ],
                [
                    "name" => "Applebot Official IP Ranges",
                    "url" => "https://search.developer.apple.com/applebot.json",
                    "file" => $this->tempDir . "/bot_apple.json",
                ],
            ],
            // 4. Tor Exit Nodes (with fallback)
            "tor" => [
                [
                    "name" => "SecOps Tor Nodes",
                    "fallback_urls" => [
                        "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
                        "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.txt",
                    ],
                    "file" => $this->tempDir . "/tor_secops.lst",
                ],
                [
                    "name" => "TorProject Bulk Exit List",
                    "url" => "https://check.torproject.org/torbulkexitlist",
                    "file" => $this->tempDir . "/tor_bulk.txt",
                ],
            ],
            // 5. IPsum
            "ipsum" => [
                [
                    "name" => "IPsum Threat Feed",
                    "url" =>
                        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                    "file" => $this->tempDir . "/ipsum.txt",
                ],
            ],
            // 6. FireHOL
            "firehol" => [
                [
                    "key" => "firehol1",
                    "name" => "FireHOL Level 1",
                    "url" =>
                        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                    "file" => $this->tempDir . "/firehol_level1.netset",
                ],
                [
                    "key" => "firehol2",
                    "name" => "FireHOL Level 2",
                    "url" =>
                        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                    "file" => $this->tempDir . "/firehol_level2.netset",
                ],
                [
                    "key" => "proxies",
                    "name" => "FireHOL Proxies",
                    "url" =>
                        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset",
                    "file" => $this->tempDir . "/firehol_proxies.netset",
                ],
            ],
            // 7. Spamhaus DROP
            "spamhaus" => [
                [
                    "name" => "Spamhaus DROP",
                    "url" => "https://www.spamhaus.org/drop/drop.txt",
                    "file" => $this->tempDir . "/spamhaus_drop.txt",
                ],
            ],
            // 8. ASN Threat Rules (Datacenter, Bad, VPN)
            "asn" => [
                [
                    "name" => "X4BNet Datacenter ASN",
                    "url" =>
                        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt",
                    "file" => $this->tempDir . "/x4bnet_dc_asn.txt",
                ],
                [
                    "name" => "X4BNet VPN ASN",
                    "url" =>
                        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt",
                    "file" => $this->tempDir . "/x4bnet_vpn_asn.txt",
                ],
                [
                    "name" => "Enesutku ASN-List",
                    "url" =>
                        "https://raw.githubusercontent.com/enesutku/ASN-List/main/asn-list.csv",
                    "file" => $this->tempDir . "/enesutku_asn.csv",
                ],
                [
                    "name" => "Brian Hama Bad ASN List",
                    "url" =>
                        "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv",
                    "file" => $this->tempDir . "/brianhama_bad_asn.csv",
                ],
            ],
            // 9. Global ASN Directory (Worldwide ASN & Organization Dictionary)
            "asn_names" => [
                [
                    "name" => "RIPE & BGP.tools Global ASN Directory",
                    "fallback_urls" => [
                        "https://ftp.ripe.net/ripe/asnames/asn.txt",
                        "https://bgp.tools/asns.csv",
                    ],
                    "file" => $this->tempDir . "/ripe_asn.txt",
                ],
            ],
        ];

        $categoryMap = [
            "vpn" => "vpn",
            "dc" => "dc",
            "dch" => "dc",
            "cloud" => "dc",
            "aws" => "dc",
            "cloudflare" => "dc",
            "oracle" => "dc",
            "do" => "dc",
            "bots" => "bots",
            "bot" => "bots",
            "crawler" => "bots",
            "crawlers" => "bots",
            "tor" => "tor",
            "ipsum" => "ipsum",
            "firehol" => "firehol",
            "firehol1" => "firehol",
            "firehol2" => "firehol",
            "proxies" => "firehol",
            "spamhaus" => "spamhaus",
            "drop" => "spamhaus",
            "asn" => "asn",
            "custom_asn" => "asn",
            "asn_names" => "asn_names",
            "asn_dir" => "asn_names",
            "directory" => "asn_names",
            "names" => "asn_names",
        ];

        $resolvedCat =
            $target !== null && isset($categoryMap[$target])
                ? $categoryMap[$target]
                : $target;

        foreach ($tasks as $cat => $items) {
            if (
                $resolvedCat !== null &&
                $resolvedCat !== $cat &&
                $resolvedCat !== "all"
            ) {
                continue;
            }

            foreach ($items as $item) {
                if (
                    isset($item["key"]) &&
                    in_array($target, ["firehol1", "firehol2", "proxies"])
                ) {
                    if ($item["key"] !== $target) {
                        continue;
                    }
                }
                logger("Downloading {$item["name"]}...");
                try {
                    if (isset($item["fallback_urls"])) {
                        FeedDownloader::downloadWithFallback(
                            $item["fallback_urls"],
                            $item["file"],
                            "logger",
                        );
                    } else {
                        FeedDownloader::download($item["url"], $item["file"]);
                        $bytes = filesize($item["file"]);
                        logger(
                            "  -> Success (" .
                                number_format($bytes) .
                                " bytes).",
                        );
                    }
                } catch (Exception $e) {
                    logger(
                        "  -> Warning: Failed to download {$item["name"]}: " .
                            $e->getMessage(),
                    );
                }
            }
        }
        logger(
            "--- [PHASE 1 COMPLETE] All raw dataset files stored in temp/ ---\n",
        );
    }

    // -------------------------------------------------------------
    // PHASE 2: MERGE, FILTER & DEDUPLICATE TO DATASET/
    // -------------------------------------------------------------

    public function mergeAndDeduplicate(?string $target = null): void
    {
        logger(
            "--- [PHASE 2] MERGING & DEDUPLICATING TO DATASET/ DIRECTORY ---",
        );

        // 1. VPN (X4BNet + Joseph Rocca)
        if ($target === null || $target === "vpn") {
            logger("Processing VPN feeds...");
            FeedMerger::mergeCidrFiles(
                [
                    $this->tempDir . "/x4bnet_vpn.txt",
                    $this->tempDir . "/josephrocca_vpn.txt",
                ],
                $this->datasetDir . "/vpn.txt",
                "logger",
            );
        }

        // 2. Datacenter & Official Cloud Providers (X4BNet + Jhassine + AWS + Cloudflare + DigitalOcean + Oracle)
        if (
            $target === null ||
            $target === "dc" ||
            $target === "dch" ||
            $target === "cloud"
        ) {
            logger("Processing Datacenter & Cloud Provider feeds...");
            FeedMerger::mergeCidrFiles(
                [
                    $this->tempDir . "/x4bnet_dc.txt",
                    $this->tempDir . "/jhassine_dc.txt",
                    $this->tempDir . "/aws_ip_ranges.json",
                    $this->tempDir . "/cloudflare_v4.txt",
                    $this->tempDir . "/digitalocean.csv",
                    $this->tempDir . "/oracle_cloud.json",
                ],
                $this->datasetDir . "/datacenter.txt",
                "logger",
            );
        }

        // 3. Search Engine Crawlers & AI Scrapers (Verified Bots)
        if (
            $target === null ||
            $target === "bots" ||
            $target === "bot" ||
            $target === "crawler"
        ) {
            logger("Processing Verified Bots & Crawlers feeds...");
            FeedMerger::mergeVerifiedBots(
                [
                    [
                        "name" => "Googlebot",
                        "category" => "SEARCH_ENGINE",
                        "file" => $this->tempDir . "/bot_google.json",
                    ],
                    [
                        "name" => "Bingbot",
                        "category" => "SEARCH_ENGINE",
                        "file" => $this->tempDir . "/bot_bing.json",
                    ],
                    [
                        "name" => "OpenAI GPTBot",
                        "category" => "AI_CRAWLER",
                        "file" => $this->tempDir . "/bot_gpt.json",
                    ],
                    [
                        "name" => "OpenAI SearchBot",
                        "category" => "AI_CRAWLER",
                        "file" => $this->tempDir . "/bot_searchbot.json",
                    ],
                    [
                        "name" => "Applebot",
                        "category" => "SEARCH_ENGINE",
                        "file" => $this->tempDir . "/bot_apple.json",
                    ],
                ],
                $this->datasetDir . "/verified_bots.txt",
                "logger",
            );
        }

        // 4. Tor Exit Nodes (SecOps + TorProject)
        if ($target === null || $target === "tor") {
            logger("Processing Tor Exit Nodes feeds...");
            FeedMerger::mergeTorFiles(
                [
                    $this->tempDir . "/tor_secops.lst",
                    $this->tempDir . "/tor_bulk.txt",
                ],
                $this->datasetDir . "/tor_exit_nodes.txt",
                "logger",
            );
        }

        // 5. IPsum Threat Feed
        if ($target === null || $target === "ipsum") {
            logger("Processing IPsum Threat Feed...");
            FeedMerger::mergeIpsumFiles(
                [$this->tempDir . "/ipsum.txt"],
                $this->datasetDir . "/ipsum.txt",
                "logger",
            );
        }

        // 6. FireHOL Level 1
        if (
            $target === null ||
            $target === "firehol" ||
            $target === "firehol1"
        ) {
            logger("Processing FireHOL Level 1...");
            FeedMerger::mergeCidrFiles(
                [$this->tempDir . "/firehol_level1.netset"],
                $this->datasetDir . "/firehol_level1.txt",
                "logger",
            );
        }

        // 7. FireHOL Level 2
        if (
            $target === null ||
            $target === "firehol" ||
            $target === "firehol2"
        ) {
            logger("Processing FireHOL Level 2...");
            FeedMerger::mergeCidrFiles(
                [$this->tempDir . "/firehol_level2.netset"],
                $this->datasetDir . "/firehol_level2.txt",
                "logger",
            );
        }

        // 8. FireHOL Proxies
        if (
            $target === null ||
            $target === "firehol" ||
            $target === "proxies"
        ) {
            logger("Processing FireHOL Aggregated Proxies...");
            FeedMerger::mergeCidrFiles(
                [$this->tempDir . "/firehol_proxies.netset"],
                $this->datasetDir . "/firehol_proxies.txt",
                "logger",
            );
        }

        // 9. Spamhaus DROP
        if ($target === null || $target === "spamhaus" || $target === "drop") {
            logger("Processing Spamhaus DROP...");
            FeedMerger::mergeCidrFiles(
                [$this->tempDir . "/spamhaus_drop.txt"],
                $this->datasetDir . "/spamhaus_drop.txt",
                "logger",
            );
        }

        // 10. Datacenter & Threat ASNs (X4BNet DC + X4BNet VPN + Enesutku + Brian Hama)
        if ($target === null || $target === "asn" || $target === "custom_asn") {
            logger("Processing Datacenter & Threat ASNs...");
            FeedMerger::mergeAsnFiles(
                [
                    $this->tempDir . "/x4bnet_dc_asn.txt",
                    $this->tempDir . "/x4bnet_vpn_asn.txt",
                    $this->tempDir . "/enesutku_asn.csv",
                    $this->tempDir . "/brianhama_bad_asn.csv",
                ],
                $this->datasetDir . "/datacenter_asns.txt",
                "logger",
            );
        }

        // 11. Global ASN Directory (RIPE NCC / BGP.tools)
        if (
            $target === null ||
            $target === "asn_names" ||
            $target === "directory" ||
            $target === "names"
        ) {
            logger("Processing Global ASN Directory (RIPE / BGP.tools)...");
            FeedMerger::mergeAsnDirectoryFiles(
                [
                    $this->tempDir . "/ripe_asn.txt",
                    $this->tempDir . "/bgp_tools_asns.csv",
                ],
                $this->datasetDir . "/asn_names.txt",
                "logger",
            );
        }

        // Purge raw files in temp/ directory
        $deleted = FileUtils::cleanDirectory($this->tempDir);
        logger("Cleaning temp/ directory: {$deleted} raw files removed.");
        logger(
            "--- [PHASE 2 COMPLETE] Clean, deduplicated files saved in dataset/ ---\n",
        );
    }

    public function showSummary(): void
    {
        echo "\n================ DATASET ARTIFACTS ON DISK ================\n";
        $datasetFiles = glob(rtrim($this->datasetDir, "/\\") . "/*.txt");
        printf(
            "%-30s | %-14s | %-12s\n",
            "Dataset Filename",
            "File Size",
            "Total Lines",
        );
        echo str_repeat("-", 62) . "\n";

        foreach ($datasetFiles as $df) {
            $base = basename($df);
            $bytes = filesize($df);
            $lineCount = 0;
            $h = fopen($df, "r");
            if ($h) {
                while (fgets($h) !== false) {
                    $lineCount++;
                }
                fclose($h);
            }
            printf(
                "%-30s | %10s KB | %10s\n",
                $base,
                number_format($bytes / 1024, 1),
                number_format($lineCount),
            );
        }
        echo str_repeat("=", 62) . "\n\n";
    }
}

// --------------------------- MAIN RUNNER ---------------------------

// Check CLI & Web parameters
$targetFeed = null;

if ($isCli) {
    foreach ($argv as $arg) {
        if (strpos($arg, "--feed=") === 0) {
            $targetFeed = strtolower(trim(substr($arg, 7)));
        }
    }
} else {
    $targetFeed = isset($_GET["feed"]) ? strtolower(trim($_GET["feed"])) : null;
}

$tempDir = __DIR__ . "/temp";
$datasetDir = __DIR__ . "/dataset";

$builder = new ThreatDatasetBuilder($tempDir, $datasetDir);

logger(
    "=== STARTING THREAT DATASET BUILDER " .
        ($targetFeed ? "[Filter: {$targetFeed}]" : "[All Feeds]") .
        " ===",
);
$totalStart = microtime(true);

// PHASE 1: Download
$builder->downloadRawSources($targetFeed);

// PHASE 2: Merge & Deduplicate
$builder->mergeAndDeduplicate($targetFeed);

$totalDuration = round(microtime(true) - $totalStart, 2);
logger("=== DATASET BUILD COMPLETED IN {$totalDuration} SECONDS ===");

// Output summary report
$builder->showSummary();
