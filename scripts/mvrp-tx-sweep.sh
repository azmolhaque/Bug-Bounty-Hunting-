#!/usr/bin/env bash
# mvrp-tx-sweep.sh — empty-parcel scan across every binder the bind test reached.
#
# Five of the seven live binders have no interface descriptor, so there is no
# AIDL to read and no token to send. An empty parcel at a few codes still
# answers the only question worth asking first: does anything check the caller,
# and if so which permission does it name.
#
# Usage:  ./mvrp-tx-sweep.sh [last-code]
set -uo pipefail
LAST="${1:-6}"
HERE="$(cd "$(dirname "$0")" && pwd)"

run() { echo; echo "######## $2"; "$HERE/mvrp-tx-scan.sh" "$1" "$2" "${3:--}" 1 "$LAST" 2>&1 | sed -n '/^code /p;/^!! /p'; }

run com.google.android.apps.messaging com.google.android.apps.messaging.external.p2p.impl.ExternalRcsEndpointService
run com.google.android.apps.messaging com.google.android.apps.messaging.backup.CustomD2DSourceEndpointService
run com.google.android.apps.photos com.google.android.apps.photos.backup.apiservice.PhotosBackupApiService
run com.google.android.apps.photos com.google.android.apps.photos.restore.apiservice.PhotosRestoreApiService
run com.google.android.apps.wear.companion com.google.android.apps.wear.companion.feature.sleepstate.server.service.SleepStateExportedService
