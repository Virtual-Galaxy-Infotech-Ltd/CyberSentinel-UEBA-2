#!/usr/bin/env bash
# preflight_probe.sh — read-only survey of a target server before installing UEBA.
#
# Run this ON the SIEM server. It CHANGES NOTHING: every command reads state or
# metadata. No file is written, no service touched, no package installed.
#
#   bash preflight_probe.sh > ueba_preflight.txt 2>&1
#
# Then send ueba_preflight.txt back. Some sections need root for process names
# and full disk visibility; run under sudo for the complete picture:
#
#   sudo bash preflight_probe.sh > ueba_preflight.txt 2>&1
#
# It deliberately does not print the contents of any config file, so no
# credentials, keys or tokens end up in the output.

s() { printf '\n\n===== %s =====\n' "$1"; }

s "0. WHO AND WHERE"
date; echo "whoami: $(whoami)"; id; hostname -f 2>/dev/null || hostname

s "1. OS AND KERNEL"
cat /etc/os-release 2>/dev/null | head -8
uname -a
echo "--- init system ---"
ps -p 1 -o comm= 2>/dev/null
command -v systemctl >/dev/null && echo "systemd: yes" || echo "systemd: NO"
command -v crontab  >/dev/null && echo "cron: yes"    || echo "cron: NO"

s "2. CPU"
nproc
lscpu 2>/dev/null | grep -iE "^(model name|socket|core|thread|cpu\(s\)|architecture)" | head -8
echo "--- load average (1/5/15 min) vs $(nproc) cores ---"
cat /proc/loadavg

s "3. MEMORY AND SWAP"
free -h
echo "--- /dev/shm size and use ---"
df -h /dev/shm 2>/dev/null

s "4. DISKS, MOUNTS, FREE SPACE   <-- decides where UEBA lives"
df -hT -x tmpfs -x devtmpfs 2>/dev/null
echo "--- block devices ---"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,ROTA 2>/dev/null
echo "--- biggest free filesystem ---"
df -P -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{print $4, $6}' | sort -rn | head -3

s "5. PYTHON TOOLCHAIN   <-- UEBA needs 3.10+, ideally 3.12"
for v in python3 python3.10 python3.11 python3.12 python3.13; do
  command -v $v >/dev/null && echo "$v -> $($v -V 2>&1)"
done
echo "--- pip / venv ---"
command -v pip3 >/dev/null && pip3 -V
python3 -c "import venv; print('venv: available')" 2>/dev/null || echo "venv: MISSING"
echo "--- build prerequisites (needed for some wheels) ---"
for b in gcc g++ make git curl rsync; do
  command -v $b >/dev/null && echo "$b: yes" || echo "$b: NO"
done
echo "--- package manager ---"
for p in apt dnf yum zypper; do command -v $p >/dev/null && echo "$p: yes"; done

s "6. WHAT IS ALREADY RUNNING   <-- co-tenancy risk"
command -v systemctl >/dev/null && systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -40
echo "--- top 15 processes by memory ---"
ps -eo pid,comm,rss,pcpu --sort=-rss 2>/dev/null | head -16
echo "--- top 10 by CPU ---"
ps -eo pid,comm,rss,pcpu --sort=-pcpu 2>/dev/null | head -11

s "7. LISTENING PORTS   <-- is 3026 free for the dashboard?"
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | head -40
echo "--- specifically 3026 / 2222 / 5000 / 8080 ---"
(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -E ":(3026|2222|5000|8080)\b" || echo "none of those are bound (good)"

s "8. THE SIEM AND ITS ENRICHMENT PIPELINE   <-- the whole point"
echo "--- candidate install roots ---"
for d in /var/ossec /opt /srv /home /usr/local /data; do
  [ -d "$d" ] && ls -1 "$d" 2>/dev/null | head -12 | sed "s|^|$d/|"
done
echo "--- anything named like the correlation / Kafka pipeline ---"
find / -maxdepth 5 -type d \( -iname "*Event-Correlation*" -o -iname "*correlation*" \
     -o -iname "*kafka*" \) -not -path "*/proc/*" 2>/dev/null | head -20

s "9. WHERE THE ENRICHED LOGS ARE WRITTEN   <-- UEBA's input"
echo "--- directories named 'enriched' ---"
find / -maxdepth 7 -type d -iname "enriched" -not -path "*/proc/*" 2>/dev/null | head -10
echo "--- files matching enriched_*.jsonl* (newest 10) ---"
find / -maxdepth 8 -type f -name "enriched_*.jsonl*" -not -path "*/proc/*" 2>/dev/null \
  | head -200 | xargs -r ls -lt 2>/dev/null | head -10
echo "--- total size and count of that directory ---"
for d in $(find / -maxdepth 7 -type d -iname "enriched" -not -path "*/proc/*" 2>/dev/null | head -3); do
  echo "$d : $(find "$d" -type f 2>/dev/null | wc -l) files, $(du -sh "$d" 2>/dev/null | cut -f1)"
done

s "10. SECURITY POLICY   <-- can block a new service binding or reading files"
command -v getenforce >/dev/null && echo "SELinux: $(getenforce)" || echo "SELinux: not installed"
command -v aa-status  >/dev/null && (aa-status --enabled && echo "AppArmor: enabled") 2>/dev/null || echo "AppArmor: not enforcing/absent"
echo "--- firewall ---"
command -v ufw >/dev/null && ufw status 2>/dev/null | head -5
command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null

s "11. GPU (expected: none, and that is fine)"
command -v nvidia-smi >/dev/null && nvidia-smi --query-gpu=name,memory.total --format=csv 2>/dev/null || echo "no nvidia-smi — CPU-only, as designed"

s "12. TIME AND LOCALE   <-- timestamps must line up with the SIEM"
timedatectl 2>/dev/null | head -6 || date
echo "TZ=$TZ"

s "DONE"
echo "Send this whole file back. Nothing above modified the system."
