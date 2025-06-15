#!/bin/bash
set -e

start_time=$(date +%s)  # Start time
# ----------- BASIC SETUP -----------
usage() {
  echo "Usage: $0 -d <domain>"
  exit 1
}

while getopts ":d:" opt; do
  case $opt in
    d) domain=$OPTARG ;;
    *) usage ;;
  esac
done

if [[ -z "$domain" ]]; then
  usage
fi

nuclei_param="-a"
outdir="output/$domain"
final_dir="$outdir/final"
mkdir -p "$outdir" "$final_dir"
final_output="$outdir/subdomain.txt"
log_file="$outdir/scan.log"
stats_file="$outdir/stats.json"
> "$final_output"
> "$log_file"

info() {
  echo "[*] $1"
}

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$log_file"
}

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo "[!] Required tool not found: $1"
    exit 1
  fi
}

# ----------- CHECK DEPENDENCIES -----------
REQUIRED_TOOLS=(subfinder assetfinder chaos jq whois curl unzip github-subdomains shodan dnsx naabu httpx nuclei gau waybackurls subzy katana)
for tool in "${REQUIRED_TOOLS[@]}"; do
  check_tool "$tool"
done

# ----------- LOGGED RUN WRAPPER -----------
run() {
  log "Running: $*"
  eval "$@" >> "$log_file" 2>&1 || true
}

merge_and_log() {
  [[ -s "$1" ]] && {
    sort -u "$1" >> "$final_output"
    count=$(wc -l < "$1")
    info "$2 found: $count"
    rm -f "$1"
  } || {
    info "$2 found: 0"
  }
}

# ----------- SUBDOMAIN ENUM -----------
run_subfinder() { run "subfinder -d $domain -silent -all -o $outdir/subfinder.txt"; merge_and_log "$outdir/subfinder.txt" "Subfinder"; }
run_assetfinder() { run "assetfinder --subs-only $domain > $outdir/assetfinder.txt"; merge_and_log "$outdir/assetfinder.txt" "Assetfinder"; }
run_github() {
  if [[ -z "$GITHUB_TOKEN" ]]; then info "GITHUB_TOKEN not set, skipping GitHub Subdomains"; return; fi
  run "github-subdomains -d $domain -t $GITHUB_TOKEN -o $outdir/github.txt"; merge_and_log "$outdir/github.txt" "GitHub Subdomains"
}

run_shodan() {
  info "Running Shodan intelligence queries..."
  local shodan_out="$outdir/shodan.txt"
  local shodan_json="$outdir/shodan_host_data.json"

  if ! shodan search --fields ip_str,port,hostnames,org,isp,asn,location.country_name,ssl.subject.cn,ssl.cert.subject.cn,ssl.cert.fingerprint.sha256 "hostname:$domain" > "$shodan_out" 2>> "$log_file"; then
    info "Shodan CLI found: 0 (no public data for $domain)"
    rm -f "$shodan_out"
    return
  fi

  info "Shodan CLI results saved: $(wc -l < "$shodan_out")"

  while read -r ip; do
    [[ -n "$ip" ]] && shodan host "$ip" --history --verbose >> "$shodan_json" 2>/dev/null || true
  done < <(cut -d':' -f1 "$outdir/subdomain_port.txt" | sort -u)

  [[ -s "$shodan_json" ]] && info "Shodan IP data enriched: $(jq length "$shodan_json" 2>/dev/null || echo 0) entries"
}

# ----------- CHAOS -----------
run_chaos_dump() {
  local chaos_index="$outdir/chaos_index.json"
  run "curl -s https://chaos-data.projectdiscovery.io/index.json -o $chaos_index"
  local chaos_url=$(grep -w "$domain" "$chaos_index" | grep "URL" | sed 's/\"URL\": \"//;s/\",//' | xargs || true)
  if [[ -n "$chaos_url" ]]; then
    (cd "$outdir" && run "curl -sSL $chaos_url -O" && unzip -qq '*.zip' && cat ./*.txt > chaos.txt && rm -f *.zip *.txt)
    merge_and_log "$outdir/chaos.txt" "Chaos Dump"
  else
    info "Chaos Dump found: 0"
  fi
  rm -f "$chaos_index"
}

run_chaos2() {
  local out="$outdir/chaos2.txt"
  run "chaos -d $domain -silent -o $out"
  merge_and_log "$out" "Chaos CLI"
}

# ----------- CRT.SH -----------
run_crtsh() {
  local out="$outdir/crtsh.txt"
  > "$out"
  local reg=$(whois "$domain" 2>/dev/null | grep -i "Registrant Organization" | cut -d ':' -f2- | xargs | sed 's/,/%2C/g; s/ /+/g')
  [[ -n "$reg" ]] && run "curl -s \"https://crt.sh/?q=$reg\" | grep -Eo '<TD>[[:alnum:]\.-]+\.[[:alpha:]]{2,}</TD>' | sed 's/<TD>//;s/<\\/TD>//' >> $out"
  run "curl -s \"https://crt.sh/?q=$domain&output=json\" | jq -r '.[].name_value' | sed 's/\\*\\.//g' >> $out"
  merge_and_log "$out" "crt.sh"
}

# ----------- DNSX ENHANCED -----------
run_dnsx() {
  local json="$outdir/dnsx_records.json" cname="$outdir/dnsx_cnames.txt" takeover="$outdir/potential_takeovers.txt"
  run "dnsx -l $final_output -a -cname -resp -json -silent -o $json"
  [[ -s "$json" ]] || { info "DNSX returned no usable data"; return; }
  jq -r 'select(.cname != null) | "\(.host)\t\(.cname)"' "$json" > "$cname" 2>>"$log_file"
  local cname_count=$(wc -l < "$cname" 2>/dev/null || echo 0)
  info "CNAME entries extracted: $cname_count"
  grep -Ei 's3\.amazonaws\.com|github\.io|herokuapp\.com|surge\.sh|fastly\.net' "$cname" > "$takeover" 2>/dev/null || true
  local takeover_count=$(wc -l < "$takeover" 2>/dev/null || echo 0)
  info "Potential subdomain takeovers: $takeover_count"
}

# ----------- NAABU WEB PORT SCAN -----------
run_naabu() {
  #local ports="7,9,13,21,22,23,25,26,37,53,66,79,80,81,82,83,84,85,88,106,110,111,113,119,135,139,143,144,179,199,443,444,457,465,513,514,515,543,544,548,554,587,631,646,7647,8000,8001,8008,8080,8081,8085,8088,8089,8090,873,8880,8888,9000,9001,9002,9080,9100,9200,9300,9443,990,993,995,9999,10000,10001,1024,1025,1026,1027,1028,1029,10443,10444,1080,1100,11000,1110,1234,12345,1241,1352,1433,1434,1521,1720,1723,1755,1900,19000,1944,2000,2001,20000,2049,20720,2121,2301,2375,2376,2717,3000,3001,3002,30821,3128,32768,3306,3389,3986,4000,4001,4002,4100,4567,4899,49152-49157,5000,5001,5002,5009,5051,5060,5101,5190,5357,5432,5601,5602,5631,5666,5800,5801,5802,5900,5985,6000,6001,6346,6347,6646,7000,7001,7002,7070,7170,7777,8222,8333,8443,8444,8500,8501,8765,8800,9443,9444,9999,10000,10444,11000,20000,20720,30821,65535"
  #local ports="7,9,13,21,22,23,25,26,37,53,66,79,80,81,82,83,84,85,88,106,110,111,113,119,135,139,143,144,179,199,443,444,457,465,513,514,515,543,544,548,554,587,631,646,7647,8000,8001,8008,8080,8081,8085,8089,8090,873,8880,8888,9000,9080,9100,990,993,995,1024,1025,1026,1027,1028,1029,10443,1080,1100,1110,1241,1352,1433,1434,1521,1720,1723,1755,1900,1944,2000,2001,2049,2121,2301,2717,3000,3001,3002,3128,32768,3306,3389,3986,4000,4001,4002,4100,4567,4899,49152-49157,5000,5001,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5801,5802,5900,5985,6000,6001,6346,6347,6646,7000,7001,7002,7070,7170,7777,8800,9999,10000,10444,11000,20000,30821"
  local ports="80,8080"
  local naabu_json="$outdir/naabu.json"
  local final_output_ports="$outdir/subdomain_port.txt"

  cmd="naabu -silent -l $final_output -p $ports -o $naabu_json -j"
  run "$cmd"

  [[ -s "$naabu_json" ]] && {
    jq -r '"\(.host):\(.port)"' "$naabu_json" | sort -u > "$final_output_ports"
    info "Naabu host:port pairs saved: $(wc -l < "$final_output_ports")"
  } || info "Naabu found: 0"
}

# ----------- HTTPX -----------
run_httpx() {
  info "Running HTTPX..."
  local httpx_domains="$outdir/httpx_subdomain_results.json"
  local httpx_ports="$outdir/httpx_portscan_results.json"

  run "httpx -silent -json -fr -l $final_output -o $httpx_domains"
  run "httpx -silent -json -fr -l $outdir/subdomain_port.txt -o $httpx_ports"

  local live_count=$(jq -r '.url' "$httpx_domains" | wc -l)
  local port_live_count=$(jq -r '.url' "$httpx_ports" | wc -l)

  info "HTTPX (subdomains): $live_count live URLs"
  info "HTTPX (host:ports): $port_live_count live URLs"
}

# ----------- NUCLEI SCAN -----------
run_nuclei() {
  info "Running Nuclei..."
  local merged_httpx="$outdir/httpx_combined.txt"
  local nuclei_json="$outdir/nuclei_results.json"
  local nuclei_dir="$outdir/nuclei"
  mkdir -p "$nuclei_dir"

  jq -r '.url' "$outdir/httpx_subdomain_results.json" "$outdir/httpx_portscan_results.json" | sort -u > "$merged_httpx"
  run "nuclei -l $merged_httpx -o $nuclei_json -jsonl"
  info "Nuclei results saved: $(wc -l < $nuclei_json)"
  rm -f "$merged_httpx"
  
  # Bersihkan semua file severity
  for sev in info low medium high critical; do
    > "$nuclei_dir/$sev.txt"
  done

  # Parsing NDJSON nuclei, output: [template-id] [type] [severity] [matched-at]
  jq -c '.' "$nuclei_json" 2>/dev/null | while read -r line; do
    template_id=$(echo "$line" | jq -r '.["template-id"] // empty')
    type=$(echo "$line" | jq -r '.type // empty')
    severity=$(echo "$line" | jq -r '.info.severity // empty')
    url=$(echo "$line" | jq -r '.["matched-at"] // empty')
    if [[ -n "$template_id" && -n "$type" && -n "$severity" && -n "$url" ]]; then
      echo "[$template_id] [$type] [$severity] $url" >> "$nuclei_dir/$severity.txt"
    fi
  done

  # Sort & hapus file kosong
  for sev in info low medium high critical; do
    [[ -s "$nuclei_dir/$sev.txt" ]] && sort -u "$nuclei_dir/$sev.txt" -o "$nuclei_dir/$sev.txt" || rm -f "$nuclei_dir/$sev.txt"
  done

  cp "$nuclei_json" "$final_dir/step_vulns.json"
}

# ----------- WAYBACKURLS -----------
run_waybackurls() {
  info "Running WaybackURLs..."
  local wayback_out="$outdir/waybackurls.txt"
  run "cat $final_output | waybackurls > $wayback_out"
  info "WaybackURLs found: $(wc -l < $wayback_out)"
}

# ----------- GAU -----------
run_gau() {
  info "Running GAU..."
  local gau_out="$outdir/gau.txt"
  run "gau $domain > $gau_out"
  info "GAU URLs collected: $(wc -l < $gau_out)"
}

# ----------- SUBZY -----------
run_subzy() {
  info "Running Subzy..."
  run "subzy run --targets $final_output --verify-ssl --hide_fails --output $outdir/subzy.txt"
  info "Subzy completed: $(wc -l < $outdir/subzy.txt) results"
}

# ----------- KATANA -----------
run_katana() {
  info "Running Katana..."
  local katana_out="$outdir/katana.txt"
  run "katana -list $outdir/httpx_subdomain_results.json -jc -o $katana_out"
  info "Katana results saved: $(wc -l < $katana_out)"
}

# ----------- URL ANALYSIS -----------
run_url_analysis() {
  info "Analyzing collected URLs and JS..."
  local all_urls="$outdir/all_urls.txt"
  local js_files="$outdir/javascript_files.txt"
  local sensitive_files="$outdir/sensitive_endpoints.txt"
  local secrets="$outdir/potential_secrets.txt"

  cat "$outdir/gau.txt" "$outdir/waybackurls.txt" "$outdir/katana.txt" 2>/dev/null | sort -u > "$all_urls"

  grep -Ei '\.js(\?|$)' "$all_urls" > "$js_files" || true
  grep -Ei '\.(env|git|bak|swp|zip|sql|conf|log)$|/(admin|login|debug|api|config)' "$all_urls" > "$sensitive_files" || true
  grep -Ei 'token=|apikey=|secret=|access[_-]?token=|bearer' "$all_urls" > "$secrets" || true

  info "JS files: $(wc -l < "$js_files")"
  info "Sensitive endpoints: $(wc -l < "$sensitive_files")"
  info "Potential secrets: $(wc -l < "$secrets")"
}

# ----------- PIPELINE -----------
info "Starting reconnaissance for: $domain"
run_subfinder
# run_assetfinder
# run_github
# run_chaos_dump
# run_chaos2
# run_crtsh

sort -u "$final_output" -o "$final_output"
info "Total unique subdomains: $(wc -l < "$final_output")"
info "Output saved to: $final_output"
echo "=========================================="
info "Running Phase 2"
run_dnsx
run_naabu
run_httpx
run_nuclei
run_shodan
# run_waybackurls
# run_gau
# run_subzy
# run_katana
# run_url_analysis

info "Scan log saved to: $log_file"

# ----------- SCAN SUMMARY OUTPUT -----------
subdomain_count=$(wc -l < "$final_output" | tr -d ' ')
port_count=$(wc -l < "$outdir/subdomain_port.txt" 2>/dev/null || echo 0)
live_count=$(jq -r '.url' "$outdir/httpx_subdomain_results.json" "$outdir/httpx_portscan_results.json" 2>/dev/null | sort -u | wc -l | tr -d ' ')
info_count=$(wc -l < "$outdir/nuclei/info.txt" 2>/dev/null || echo 0)
low_count=$(wc -l < "$outdir/nuclei/low.txt" 22>/dev/null || echo 0)
med_count=$(wc -l < "$outdir/nuclei/medium.txt" 2>/dev/null || echo 0)
high_count=$(wc -l < "$outdir/nuclei/high.txt" 2>/dev/null || echo 0)
crit_count=$(wc -l < "$outdir/nuclei/critical.txt" 2>/dev/null || echo 0)

end_time=$(date +%s)
duration=$((end_time - start_time))
duration_str=""
if (( duration >= 3600 )); then
  hours=$((duration / 3600))
  minutes=$(((duration % 3600) / 60))
  seconds=$((duration % 60))
  duration_str="$hours hour $minutes minutes $seconds seconds"
elif (( duration >= 60 )); then
  minutes=$((duration / 60))
  seconds=$((duration % 60))
  duration_str="$minutes minutes $seconds seconds"
else
  duration_str="$duration seconds"
fi

jq -n --arg domain "$domain" \
      --arg subs "$subdomain_count" \
      --arg ports "$port_count" \
      --arg live "$live_count" \
      --arg info "$info_count" \
      --arg low "$low_count" \
      --arg medium "$med_count" \
      --arg high "$high_count" \
      --arg critical "$crit_count" \
      --arg duration "$duration_str" \
      '{domain: $domain, subdomains: $subs, open_ports: $ports, live_hosts: $live, vulnerabilities: {info: $info, low: $low, medium: $medium, high: $high, critical: $critical}, scan_duration: $duration}' > "$stats_file"

info "Stats saved to: $stats_file"