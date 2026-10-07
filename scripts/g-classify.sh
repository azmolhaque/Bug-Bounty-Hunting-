#!/data/data/com.termux/files/usr/bin/bash
# g-classify.sh — read a sweep against its own sentinels.
#   bash scripts/g-classify.sh results/google/sweep-acq.tsv
T="${1:?usage: g-classify.sh <sweep.tsv>}"

echo "===== SENTINELS (apexes with wildcard DNS) ====="
awk -F'\t' '$2=="SENTINEL" && $4!="NODNS"{printf "  %-44s %s %sb  -> every sibling must be read against this\n",$1,$4,$5}' "$T"
awk -F'\t' '$2=="SENTINEL" && $4!="NODNS"{print $1"\t"$4"\t"$5}' "$T" | sed 's/^zzz-canary-7x2\.//' > /data/data/com.termux/files/usr/tmp/.wc 2>/dev/null \
  || awk -F'\t' '$2=="SENTINEL" && $4!="NODNS"{print $1"\t"$4"\t"$5}' "$T" | sed 's/^zzz-canary-7x2\.//' > "$HOME/.wildcards.tsv"
W="$HOME/.wildcards.tsv"

echo
echo "===== ANSWERED, NO IDENTITY GATE  (the only rows worth a second look) ====="
awk -F'\t' -v W="$W" '
BEGIN{ while((getline l < W)>0){split(l,a,"\t"); wc[a[1]]=a[2]" "a[3]} }
$2=="SENTINEL" || $4=="NODNS" || $4=="ERR" || $4=="000" {next}
{
  n=split($1,p,"."); apex=p[n-1]"."p[n]
  if (apex in wc) { split(wc[apex],s," "); if ($4==s[1] && $5==s[2]) next }   # identical to canary
  if ($7 ~ /accounts\.google\.com|okta|login\.|signin|auth0|iap\.googleapis/) next
  if ($4 ~ /^(301|302|303|307|308)$/ && $7 != "-") next
  printf "  %-44s %-6s %-4s %8sb  %-22s %s\n",$1,$2,$4,$5,$6,$7
}' "$T"

echo
echo "===== REDIRECTED TO AN IDENTITY PROVIDER (closed, for the record) ====="
awk -F'\t' '$7 ~ /accounts\.google\.com|okta|iap\.googleapis|signin|login/{printf "  %-44s %s\n",$1,$4}' "$T" | head -20

echo
echo "===== TALLY ====="
awk -F'\t' 'NR>1{c[$4]++} END{for(k in c) printf "  %-8s %d\n",k,c[k]}' "$T" | sort -k2 -rn
