import os
import geoip2.database
import requests

# Test IP: Cloudflare Public DNS
TEST_IP = "1.1.1.1"

# Load API key from environment or insert temporarily for testing
API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_API_KEY_HERE")
CITY_DB = "data/GeoLite2-City.mmdb"
ASN_DB = "data/GeoLite2-ASN.mmdb"

print(f"[*] Testing enrichment on IP: {TEST_IP}\n")

# 1. Test MaxMind GeoLite2 City
try:
    with geoip2.database.Reader(CITY_DB) as reader:
        city_res = reader.city(TEST_IP)
        print(f"[+] GeoIP City Success:")
        print(f"    - Country: {city_res.country.name} ({city_res.country.iso_code})")
        print(f"    - Coordinates: {city_res.location.latitude}, {city_res.location.longitude}")
except Exception as e:
    print(f"[-] GeoIP City Failed: {e}")

# 2. Test MaxMind GeoLite2 ASN
try:
    with geoip2.database.Reader(ASN_DB) as reader:
        asn_res = reader.asn(TEST_IP)
        print(f"[+] GeoIP ASN Success:")
        print(f"    - ASN: AS{asn_res.autonomous_system_number}")
        print(f"    - Organization: {asn_res.autonomous_system_organization}")
except Exception as e:
    print(f"[-] GeoIP ASN Failed: {e}")

# 3. Test AbuseIPDB API
if not API_KEY or API_KEY == "YOUR_API_KEY_HERE":
    print("[-] AbuseIPDB Skipped: No API key detected. Set ABUSEIPDB_API_KEY first.")
else:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": API_KEY}
    params = {"ipAddress": TEST_IP, "maxAgeInDays": "90"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            print(f"[+] AbuseIPDB API Success:")
            print(f"    - Abuse Confidence Score: {data.get('abuseConfidenceScore')}%")
            print(f"    - Total Reports: {data.get('totalReports')}")
            print(f"    - Whitelisted: {data.get('isWhitelisted')}")
        else:
            print(f"[-] AbuseIPDB Error HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"[-] AbuseIPDB Connection Error: {e}")