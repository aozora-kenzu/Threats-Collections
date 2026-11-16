<?php
/**
 * Threat Feeds Helpers
 *
 * Supporting modules for the Threat Feeds ETL pipeline:
 * - FileUtils: Directory management utilities (temp, dataset)
 * - FeedDownloader: Memory-efficient streaming cURL downloader with fallback support
 * - FeedNormalizer: CIDR/IP format cleaner and 32-bit unsigned integer subnet math
 * - FeedMerger: Deduplication and multi-source merger across datasets
 */

class FileUtils
{
    /**
     * Ensures that a directory exists and is writable.
     */
    public static function ensureDir(string $dir): void
    {
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
    }

    /**
     * Deletes all files in a directory without removing the directory itself.
     */
    public static function cleanDirectory(string $dir): int
    {
        if (!is_dir($dir)) {
            return 0;
        }

        $count = 0;
        $files = glob(rtrim($dir, "/\\") . "/*");
        foreach ($files as $file) {
            if (is_file($file)) {
                @unlink($file);
                $count++;
            }
        }
        return $count;
    }
}

class FeedDownloader
{
    /**
     * Downloads a file from a URL directly to disk using streaming cURL.
     */
    public static function download(
        string $url,
        string $destPath,
        int $timeout = 300,
    ): void {
        FileUtils::ensureDir(dirname($destPath));

        $fp = fopen($destPath, "w+");
        if (!$fp) {
            throw new RuntimeException(
                "Failed to create target file: {$destPath}",
            );
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_USERAGENT => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatFeedBot/2.0",
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
        ]);

        $success = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if (!$success || $httpCode < 200 || $httpCode >= 300) {
            @unlink($destPath);
            throw new RuntimeException(
                "Failed to download {$url} (HTTP {$httpCode}): {$error}",
            );
        }
    }

    /**
     * Downloads with fallback: tries primary URL, then tries subsequent backup URLs upon failure.
     */
    public static function downloadWithFallback(
        array $urls,
        string $destPath,
        ?callable $logger = null,
        int $timeout = 180,
    ): string {
        $lastError = "";
        foreach ($urls as $idx => $url) {
            $isFallback = $idx > 0;
            $label = $isFallback ? "Fallback #" . $idx : "Primary";
            if ($logger) {
                $logger("  Attempting download [{$label}]: {$url}");
            }

            try {
                self::download($url, $destPath, $timeout);
                if ($logger) {
                    $size = filesize($destPath);
                    $logger(
                        "    -> Successfully downloaded (" .
                            number_format($size) .
                            " bytes).",
                    );
                }
                return $url;
            } catch (Exception $e) {
                $lastError = $e->getMessage();
                if ($logger) {
                    $logger("    -> Failed: {$lastError}");
                }
            }
        }

        throw new RuntimeException("All URLs failed to download: {$lastError}");
    }
}

class FeedNormalizer
{
    /**
     * Cleans and validates a line string into a clean IPv4 CIDR format (e.g. 1.2.3.0/24).
     * Ignores empty lines, comments (#, ;), and IPv6 addresses.
     */
    public static function cleanCidr(string $line): ?string
    {
        // Strip inline comments if present (e.g., Spamhaus '; SBL...')
        if (($semicolonPos = strpos($line, ";")) !== false) {
            $line = substr($line, 0, $semicolonPos);
        }

        $cidr = trim($line);
        if ($cidr === "" || $cidr[0] === "#") {
            return null;
        }

        // Ignore IPv6
        if (strpos($cidr, ":") !== false) {
            return null;
        }

        // If single IP without subnet mask, append /32
        if (strpos($cidr, "/") === false) {
            $cidr .= "/32";
        }

        [$ip, $maskBitsStr] = explode("/", $cidr, 2);
        $maskBits = (int) $maskBitsStr;
        if ($maskBits < 0 || $maskBits > 32) {
            return null;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }

        return $ip . "/" . $maskBits;
    }

    /**
     * Converts an IPv4 CIDR into a 32-bit unsigned integer range (start_int, end_int, prefix_8).
     */
    public static function cidrToIntegerRange(string $cidr): ?array
    {
        [$ip, $maskBitsStr] = explode("/", $cidr, 2);
        $maskBits = (int) $maskBitsStr;
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return null;
        }

        $ipStart = sprintf("%u", $ipLong);
        $prefix8 = (int) explode(".", $ip)[0];

        if ($maskBits === 32) {
            $ipEnd = $ipStart;
        } else {
            $wildcard = (1 << (32 - $maskBits)) - 1;
            $mask = ~$wildcard & 0xffffffff;
            $ipStart = (int) ($ipStart & $mask);
            $ipEnd = (int) ($ipStart | $wildcard);
        }

        return [
            "prefix_8" => $prefix8,
            "ip_start_int" => $ipStart,
            "ip_end_int" => $ipEnd,
            "cidr" => $cidr,
        ];
    }
}

class FeedMerger
{
    /**
     * Merges one or more CIDR/IP source files, eliminates duplicates,
     * and saves into a clean normalized .txt output file.
     * Supports plain text, JSON (AWS, Oracle), and CSV (DigitalOcean) formats.
     */
    public static function mergeCidrFiles(
        array $inputPaths,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $unique = [];
        $totalRaw = 0;

        foreach ($inputPaths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

            // Case 1: JSON files (AWS ip-ranges.json, Oracle Cloud public_ip_ranges.json)
            if ($ext === "json") {
                $content = file_get_contents($path);
                if ($content !== false && $content !== "") {
                    $data = json_decode($content, true);
                    if (isset($data["prefixes"])) {
                        foreach ($data["prefixes"] as $p) {
                            $totalRaw++;
                            if (isset($p["ip_prefix"])) {
                                $clean = FeedNormalizer::cleanCidr(
                                    $p["ip_prefix"],
                                );
                                if ($clean !== null) {
                                    $unique[$clean] = true;
                                }
                            }
                        }
                    }
                    if (isset($data["regions"])) {
                        foreach ($data["regions"] as $r) {
                            if (isset($r["cidrs"])) {
                                foreach ($r["cidrs"] as $c) {
                                    $totalRaw++;
                                    if (isset($c["cidr"])) {
                                        $clean = FeedNormalizer::cleanCidr(
                                            $c["cidr"],
                                        );
                                        if ($clean !== null) {
                                            $unique[$clean] = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                continue;
            }

            // Case 2: CSV files (DigitalOcean google.csv)
            if ($ext === "csv") {
                $fp = fopen($path, "r");
                if ($fp) {
                    while (($line = fgets($fp)) !== false) {
                        $totalRaw++;
                        $parts = str_getcsv($line, ",", "\"", "\\");
                        if (isset($parts[0])) {
                            $clean = FeedNormalizer::cleanCidr($parts[0]);
                            if ($clean !== null) {
                                $unique[$clean] = true;
                            }
                        }
                    }
                    fclose($fp);
                }
                continue;
            }

            // Case 3: Standard Text / Netset files (X4BNet, Jhassine, Cloudflare, FireHOL, Spamhaus)
            $fp = fopen($path, "r");
            if (!$fp) {
                continue;
            }

            while (($line = fgets($fp)) !== false) {
                $totalRaw++;
                $clean = FeedNormalizer::cleanCidr($line);
                if ($clean !== null) {
                    $unique[$clean] = true;
                }
            }
            fclose($fp);
        }

        $uniqueCount = count($unique);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  CIDR Deduplication: from " .
                    number_format($totalRaw) .
                    " raw lines to " .
                    number_format($uniqueCount) .
                    " unique CIDRs.",
            );
        }

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($unique as $cidr => $_) {
            fwrite($outFp, $cidr . "\n");
        }
        fclose($outFp);

        return $uniqueCount;
    }

    /**
     * Merges official search engine and AI crawler bot feeds (Googlebot, Bingbot, GPTBot, SearchBot, Applebot).
     * Output format: <cidr>\t<bot_name>\t<category>
     */
    public static function mergeVerifiedBots(
        array $botItems,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $unique = [];
        $totalRaw = 0;

        foreach ($botItems as $item) {
            $path = $item["file"];
            $botName = $item["name"];
            $category = $item["category"];

            if (!file_exists($path)) {
                continue;
            }

            $content = file_get_contents($path);
            if ($content === false || trim($content) === "") {
                continue;
            }

            $cidrs = [];
            if ($content[0] === "{" || strpos(trim($content), "{") === 0) {
                $data = json_decode($content, true);
                if (isset($data["prefixes"])) {
                    foreach ($data["prefixes"] as $p) {
                        if (isset($p["ipv4Prefix"])) {
                            $cidrs[] = $p["ipv4Prefix"];
                        } elseif (isset($p["ip_prefix"])) {
                            $cidrs[] = $p["ip_prefix"];
                        }
                    }
                }
            } else {
                foreach (explode("\n", $content) as $line) {
                    $c = FeedNormalizer::cleanCidr($line);
                    if ($c !== null) {
                        $cidrs[] = $c;
                    }
                }
            }

            foreach ($cidrs as $rawCidr) {
                $totalRaw++;
                $clean = FeedNormalizer::cleanCidr($rawCidr);
                if ($clean !== null) {
                    $unique[$clean] = [
                        "bot_name" => $botName,
                        "category" => $category,
                    ];
                }
            }
        }

        $uniqueCount = count($unique);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  Verified Bots Deduplication: from " .
                    number_format($totalRaw) .
                    " raw entries to " .
                    number_format($uniqueCount) .
                    " unique bot CIDRs.",
            );
        }

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($unique as $cidr => $info) {
            fwrite(
                $outFp,
                "{$cidr}\t{$info["bot_name"]}\t{$info["category"]}\n",
            );
        }
        fclose($outFp);

        return $uniqueCount;
    }

    /**
     * Merges Tor Exit Node files, extracts unique IPv4 addresses, and writes them to the output file.
     */
    public static function mergeTorFiles(
        array $inputPaths,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $uniqueIps = [];
        $totalRaw = 0;

        foreach ($inputPaths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $fp = fopen($path, "r");
            if (!$fp) {
                continue;
            }

            while (($line = fgets($fp)) !== false) {
                $totalRaw++;
                $line = trim($line);
                if ($line === "" || $line[0] === "#") {
                    continue;
                }

                if (
                    preg_match(
                        "/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/",
                        $line,
                        $matches,
                    )
                ) {
                    $ip = $matches[0];
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $uniqueIps[$ip] = true;
                    }
                }
            }
            fclose($fp);
        }

        $uniqueCount = count($uniqueIps);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  Tor Deduplication: from " .
                    number_format($totalRaw) .
                    " raw lines to " .
                    number_format($uniqueCount) .
                    " unique IPs.",
            );
        }

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($uniqueIps as $ip => $_) {
            fwrite($outFp, $ip . "\n");
        }
        fclose($outFp);

        return $uniqueCount;
    }

    /**
     * Processes IPsum files (IP + Hits), keeping the highest hit count for duplicate IPs.
     */
    public static function mergeIpsumFiles(
        array $inputPaths,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $unique = [];
        $totalRaw = 0;

        foreach ($inputPaths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $fp = fopen($path, "r");
            if (!$fp) {
                continue;
            }

            while (($line = fgets($fp)) !== false) {
                $totalRaw++;
                $line = trim($line);
                if ($line === "" || $line[0] === "#") {
                    continue;
                }

                $parts = preg_split("/\\s+/", $line);
                if (empty($parts[0])) {
                    continue;
                }

                $ip = $parts[0];
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    continue;
                }

                $hits = isset($parts[1]) ? (int) $parts[1] : 1;
                if (!isset($unique[$ip]) || $hits > $unique[$ip]) {
                    $unique[$ip] = $hits;
                }
            }
            fclose($fp);
        }

        $uniqueCount = count($unique);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  IPsum Deduplication: from " .
                    number_format($totalRaw) .
                    " raw lines to " .
                    number_format($uniqueCount) .
                    " unique IPs.",
            );
        }

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($unique as $ip => $hits) {
            fwrite($outFp, "{$ip}\t{$hits}\n");
        }
        fclose($outFp);

        return $uniqueCount;
    }

    /**
     * Merges Threat ASN datasets (X4BNet DC ASN, X4BNet VPN ASN, Enesutku ASN, Brian Hama Bad ASN).
     * Output format: <asn_number>\t<name>
     */
    public static function mergeAsnFiles(
        array $inputPaths,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $asns = [];
        $totalRaw = 0;

        foreach ($inputPaths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $fp = fopen($path, "r");
            if (!$fp) {
                continue;
            }

            while (($line = fgets($fp)) !== false) {
                $totalRaw++;
                $line = trim($line);
                if ($line === "" || $line[0] === "#") {
                    continue;
                }

                // Format 1: X4BNet "AS<num> # Description"
                if (preg_match("/^AS(\\d+)(?:\\s*#\\s*(.*))?/i", $line, $m)) {
                    $num = (int) $m[1];
                    $name =
                        isset($m[2]) && trim($m[2]) !== ""
                            ? trim($m[2])
                            : "AS" . $num;
                    if (
                        !isset($asns[$num]) ||
                        strpos($asns[$num], "AS" . $num) === 0
                    ) {
                        $asns[$num] = $name;
                    }
                    continue;
                }

                // Ignore CSV header line
                if (
                    stripos($line, "ASN,") === 0 ||
                    stripos($line, "asn,") === 0
                ) {
                    continue;
                }

                // Format 2: CSV "ASN,Entity" (Enesutku & Brian Hama)
                $parts = str_getcsv($line, ",", "\"", "\\");
                if (isset($parts[0])) {
                    $rawAsn = trim($parts[0]);
                    if (preg_match('/^(?:AS)?(\\d+)$/i', $rawAsn, $am)) {
                        $num = (int) $am[1];
                        $name =
                            isset($parts[1]) && trim($parts[1]) !== ""
                                ? trim($parts[1])
                                : "AS" . $num;
                        if (
                            !isset($asns[$num]) ||
                            strpos($asns[$num], "AS" . $num) === 0
                        ) {
                            $asns[$num] = $name;
                        }
                    }
                }
            }
            fclose($fp);
        }

        $uniqueCount = count($asns);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  Threat ASN Rules Deduplication: from " .
                    number_format($totalRaw) .
                    " raw lines to " .
                    number_format($uniqueCount) .
                    " unique ASNs.",
            );
        }

        ksort($asns); // Sort by ASN number

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($asns as $num => $name) {
            fwrite($outFp, "{$num}\t{$name}\n");
        }
        fclose($outFp);

        return $uniqueCount;
    }

    /**
     * Merges global ASN name directories (RIPE NCC / BGP.tools).
     * Output format: <asn_number>\t<name>\t<country_code>
     */
    public static function mergeAsnDirectoryFiles(
        array $inputPaths,
        string $outputPath,
        ?callable $logger = null,
    ): int {
        FileUtils::ensureDir(dirname($outputPath));

        $asns = [];
        $totalRaw = 0;

        foreach ($inputPaths as $path) {
            if (!file_exists($path)) {
                continue;
            }

            $fp = fopen($path, "r");
            if (!$fp) {
                continue;
            }

            while (($line = fgets($fp)) !== false) {
                $totalRaw++;
                $line = trim($line);
                if ($line === "" || $line[0] === "#") {
                    continue;
                }

                // Ignore BGP.tools header (asn,name,class,cc)
                if (stripos($line, "asn,name") === 0) {
                    continue;
                }

                // Format 1: BGP.tools CSV "AS10,CSNET Coordination,Unknown,US"
                if (
                    stripos($line, "AS") === 0 &&
                    strpos($line, ",") !== false
                ) {
                    $parts = str_getcsv($line, ",", "\"", "\\");
                    if (
                        isset($parts[0]) &&
                        preg_match('/^AS(\\d+)$/i', trim($parts[0]), $m)
                    ) {
                        $num = (int) $m[1];
                        $name = isset($parts[1])
                            ? trim($parts[1])
                            : "AS" . $num;
                        $cc =
                            isset($parts[3]) && trim($parts[3]) !== ""
                                ? strtoupper(trim($parts[3]))
                                : "";
                        if (
                            !isset($asns[$num]) ||
                            strpos($asns[$num]["name"], "AS" . $num) === 0
                        ) {
                            $asns[$num] = ["name" => $name, "cc" => $cc];
                        }
                        continue;
                    }
                }

                // Format 2: RIPE format "1 LVLT-1 - Level 3 Parent, LLC, US"
                if (preg_match('/^(\\d+)\\s+(.+)$/', $line, $m)) {
                    $num = (int) $m[1];
                    $desc = trim($m[2]);
                    $cc = "";
                    if (preg_match('/,\\s*([A-Z]{2})$/', $desc, $cm)) {
                        $cc = $cm[1];
                    }
                    if (
                        !isset($asns[$num]) ||
                        strpos($asns[$num]["name"], "AS" . $num) === 0
                    ) {
                        $asns[$num] = ["name" => $desc, "cc" => $cc];
                    }
                }
            }
            fclose($fp);
        }

        $uniqueCount = count($asns);
        if ($uniqueCount === 0) {
            if ($logger) {
                $logger(
                    "  Warning: No source data found for {$outputPath}. Preserving existing file.",
                );
            }
            return file_exists($outputPath) ? count(file($outputPath)) : 0;
        }

        if ($logger) {
            $logger(
                "  Global ASN Directory Deduplication: from " .
                    number_format($totalRaw) .
                    " raw lines to " .
                    number_format($uniqueCount) .
                    " unique entries.",
            );
        }

        ksort($asns);

        $outFp = fopen($outputPath, "w");
        if (!$outFp) {
            throw new RuntimeException("Failed to write to {$outputPath}");
        }

        foreach ($asns as $num => $info) {
            $name = $info["name"];
            $cc = $info["cc"];
            fwrite($outFp, "{$num}\t{$name}\t{$cc}\n");
        }
        fclose($outFp);

        return $uniqueCount;
    }
}
