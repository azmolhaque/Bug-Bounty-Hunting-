#!/usr/bin/env bash
# mvrp-bcast.sh — BLE_SCANNED broadcast রেকর্ড, সংক্ষেপে।
#
# `dumpsys activity broadcasts` কয়েক হাজার লাইন — টার্মিনাল ভেসে যায়।
# এখান থেকে শুধু তিনটে জিনিস তোলা হয়: কে পাঠাল, deliver হলো কিনা, আর কখন।
#
# কেন দরকার: ইতিহাস দেখাচ্ছে ওই receiver নিয়মিত BLE_SCANNED পায়, আর
# অনেকগুলোয় disp=1970 (কখনো dispatch হয়নি)। কোনটা কার, সেটা caller ছাড়া
# বলা যায় না — আর caller লাইনটা আলাদা ব্লকে থাকে।
set -uo pipefail
ACT="${1:-BLE_SCANNED}"
N="${2:-25}"
adb shell dumpsys activity broadcasts 2>/dev/null </dev/null | tr -d '\r' \
| awk -v act="$ACT" '
  /^ *BroadcastRecord\{/ { rec=$0; caller=""; outcome=""; when=""; has=0 }
  index($0, act) && rec!="" { has=1 }
  /caller=/ { c=$0; sub(/.*caller=/,"",c); sub(/ .*/,"",c); caller=c }
  /enqueueClockTime=/ { w=$0; sub(/.*enqueueClockTime=/,"",w); sub(/ dispatchClockTime.*/,"",w); when=w
                        d=$0; sub(/.*dispatchClockTime=/,"",d); disp=d }
  /DELIVERED/ && has && outcome=="" { outcome="DELIVERED" }
  /SKIPPED/   && has && outcome=="" { outcome="SKIPPED" }
  /^ *reason: skipped by policy/ { why=$0; sub(/.*Permission Denial: /,"",why); sub(/ from .*/,"",why) }
  /^ *(Historical Broadcast|BroadcastRecord\{)/ {
     if (has && caller!="" ) {
        printf "%-20s %-28s %-10s %s\n", when, caller, outcome, (disp ~ /^1970/ ? "(never dispatched)" : "")
     }
     has=0; caller=""; outcome=""; disp=""
  }
' | sort -u | tail -"$N"
