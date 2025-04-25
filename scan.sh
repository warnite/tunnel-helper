#!/usr/bin/env bash
set -uo pipefail
IFS=$'\n'

LOG_FILE="${PWD}/operations.log"
:> "$LOG_FILE"

open_results=$(mktemp)
LOCAL_STATE="${PWD}/local_port.state"
REMOTE_STATE="${PWD}/remote_port.state"
DYN_ACTIVE=0
DYN_PORT=

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

perform_scan() {
  :> "$open_results"
  log "Scanning ${net}.${start}→${net}.${end} on ports: $ports"
  for ((i = start; i <= end; i++)); do
    host="${net}.${i}"
    {
      nc -zv -w1 "$host" $ports < /dev/null 2>&1 \
        | grep -E 'succeeded|open' \
        | awk -v h="$host" '{ print h, $4 }' \
        >>"$open_results" || true
    } &
  done
  wait
  log "Scan results in $open_results"
}

perform_wget() {
  local mode=$1 cmd
  [[ "$mode" == "proxy" ]] && cmd="proxychains wget" || cmd="wget"
  log "Downloading ($mode) from FTP/HTTP hosts"
  sort -u "$open_results" | while read -r host port; do
    case $port in
      21) url="ftp://$host" ;;
      80) url="http://$host" ;;
      *) continue ;;
    esac
    log " -> $cmd -r $url"
    $cmd -r "$url" &>> "$LOG_FILE"
    log "    exit code: $?"
  done
}

perform_banner_grab() {
  read -r -p "Use proxychains for banner grabbing? (y/n): " use
  if [[ "$use" =~ ^[Yy]$ ]]; then
    NC_CMD=(proxychains nc)
    log "Banner grabbing via proxychains"
  else
    NC_CMD=(nc)
    log "Banner grabbing directly"
  fi

  scan_results="${PWD}/${net}-scan.txt"
  :> "$scan_results"
  log "Grabbing banners"
  while read -r host port; do
    banner=$( { echo; sleep 1; } | "${NC_CMD[@]}" "$host" "$port" -w2 2>/dev/null )
    banner=${banner//$'\r'/ }; banner=${banner//$'\n'/ }; banner=${banner//  / }
    printf '%s %s %s\n' "$host" "$port" "${banner:-<no-banner>}" \
      | tee -a "$scan_results" >>"$LOG_FILE"
    log "Banner for $host:$port => ${banner:-<no-banner>}"
  done <"$open_results"
  log "Banners in $scan_results"
}

ssh_connection() {
  read -r -p "SSH username: " remote_user
  read -s -p "SSH password: " remote_pass; echo
  mapfile -t hosts < <(awk '$2==22{print $1}' "$open_results" | sort -u)
  (( ${#hosts[@]} )) || { log "No SSH hosts found"; return; }
  log "SSH connection: found hosts ${hosts[*]}"
  for i in "${!hosts[@]}"; do printf "  %d) %s\n" $((i+1)) "${hosts[i]}"; done
  read -r -p "Select host #: " sel
  host="${hosts[sel-1]}"
  SSH_CMD=(sshpass -p "$remote_pass" ssh -o StrictHostKeyChecking=no)
  (( DYN_ACTIVE )) && SSH_CMD=(proxychains "${SSH_CMD[@]}")
  "${SSH_CMD[@]}" "$remote_user@$host" "ip a; lsof; ss -ntlp" 2>&1 | tee -a "$LOG_FILE"
  log "SSH connection completed on $host"
}

telnet_connection() {
  read -r -p "Telnet username: " remote_user
  read -s -p "Telnet password: " remote_pass; echo
  mapfile -t hosts < <(awk '$2==23{print $1}' "$open_results" | sort -u)
  (( ${#hosts[@]} )) || { log "No Telnet hosts found"; return; }
  log "Telnet connection: found hosts ${hosts[*]}"
  for i in "${!hosts[@]}"; do printf "  %d) %s\n" $((i+1)) "${hosts[i]}"; done
  read -r -p "Select host #: " sel
  host="${hosts[sel-1]}"
  TEL_CMD=(telnet)
  (( DYN_ACTIVE )) && TEL_CMD=(proxychains "${TEL_CMD[@]}")
  {
    echo "$remote_user"; sleep 1
    echo "$remote_pass"; sleep 1
    echo "ip a"; echo "lsof"; echo "ss -ntlp"; echo "exit"
  } | "${TEL_CMD[@]}" "$host" 23 2>&1 | tee -a "$LOG_FILE"
  log "Telnet connection completed on $host"
}

base64_encode() {
  read -r -p "String to encode: " input
  result=$(echo -n "$input" | base64)
  log "Base64('$input') => $result"
  echo "$result"
}

md5_encode() {
  read -r -p "String to hash: " input
  read -r -p "Salt (optional): " salt
  if [[ -n "$salt" ]]; then
    tohash="$input $salt"
  else
    tohash="$input"
  fi
  hash_output=$(echo "$tohash" | md5sum)
  log "echo \"$tohash\" | md5sum => $hash_output"
  echo "$hash_output"
}

create_dynamic_tunnel() {
  read -r -p "SSH username: " remote_user
  read -s -p "SSH password: " remote_pass; echo
  read -r -p "Remote host for dynamic tunnel: " DYN_HOST
  read -r -p "Local SOCKS port (e.g. 1080): " DYN_PORT
  log "Starting dynamic tunnel to $DYN_HOST:$DYN_PORT"
  sshpass -p "$remote_pass" ssh -f -N -D "$DYN_PORT" \
    -o StrictHostKeyChecking=no "$remote_user@$DYN_HOST"
  DYN_ACTIVE=1
  log "Dynamic tunnel on localhost:$DYN_PORT"
}

create_local_forwards() {
  read -r -p "SSH username: " remote_user
  read -s -p "SSH password: " remote_pass; echo
  read -r -p "Remote host for local tunnel: " host
  read -r -p "Port range (start-end): " range
  IFS=- read -r pstart pend <<<"$range"
  [[ -f "$LOCAL_STATE" ]] || echo "$pstart" >"$LOCAL_STATE"
  port=$(<"$LOCAL_STATE"); (( port>pend )) && port=$pstart

  read -r -p "Use dynamic tunnel? (y/n): " use
  proxy_opt=(); [[ "$use" =~ ^[Yy]$ && DYN_ACTIVE ]] && \
    proxy_opt=(-o "ProxyCommand=nc -X 5 -x localhost:$DYN_PORT %h %p")

  log "Local forward localhost:$port → $host:$port"
  sshpass -p "$remote_pass" ssh "${proxy_opt[@]}" -f -N \
    -L "$port:localhost:$port" -o StrictHostKeyChecking=no "$remote_user@$host"
  echo $((port+1)) >"$LOCAL_STATE"
}

create_remote_forwards() {
  read -r -p "SSH username: " remote_user
  read -s -p "SSH password: " remote_pass; echo
  read -r -p "Remote host for remote tunnel: " host
  read -r -p "Port range (start-end): " range
  IFS=- read -r pstart pend <<<"$range"
  [[ -f "$REMOTE_STATE" ]] || echo "$pstart" >"$REMOTE_STATE"
  port=$(<"$REMOTE_STATE"); (( port>pend )) && port=$pstart

  read -r -p "Use dynamic tunnel? (y/n): " use
  proxy_opt=(); [[ "$use" =~ ^[Yy]$ && DYN_ACTIVE ]] && \
    proxy_opt=(-o "ProxyCommand=nc -X 5 -x localhost:$DYN_PORT %h %p")

  log "Remote forward $host:$port → localhost:$port"
  sshpass -p "$remote_pass" ssh "${proxy_opt[@]}" -f -N \
    -R "$port:localhost:$port" -o StrictHostKeyChecking=no "$remote_user@$host"
  echo $((port+1)) >"$REMOTE_STATE"
}

while true; do
  cat <<EOF

Menu:
  1) Scan only
  2) Scan + wget plain
  3) Scan + wget proxy
  4) Scan + banner-grab
  5) SSH connection
  6) Telnet connection
  7) Base64-encode
  8) MD5-encode
  9) Create dynamic tunnel
 10) Create next local forward tunnel
 11) Create next remote forward tunnel
 12) Exit

EOF
  read -r -p "Choice [1-12]: " choice
  case "$choice" in
    1)
      read -r -p "Network (e.g. 192.168.0): " net
      read -r -p "Host start (1–254): " start
      read -r -p "Host end   (1–254): " end
      read -r -p "Ports (e.g. 21 22 80): " ports
      perform_scan
      ;;
    2)
      read -r -p "Network: " net
      read -r -p "Start: " start
      read -r -p "End:   " end
      read -r -p "Ports: " ports
      perform_scan
      perform_wget plain
      ;;
    3)
      read -r -p "Network: " net
      read -r -p "Start: " start
      read -r -p "End:   " end
      read -r -p "Ports: " ports
      perform_scan
      perform_wget proxy
      ;;
    4)
      read -r -p "Network: " net
      read -r -p "Start: " start
      read -r -p "End:   " end
      read -r -p "Ports: " ports
      perform_scan
      perform_banner_grab
      ;;
    5)  ssh_connection ;;
    6)  telnet_connection ;;
    7)  base64_encode ;;
    8)  md5_encode ;;
    9)  create_dynamic_tunnel ;;
    10) create_local_forwards ;;
    11) create_remote_forwards ;;
    12) log "Exiting."; break ;;
    *)  log "Invalid choice: $choice" ;;
  esac
done
