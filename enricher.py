import ipaddress
import json
import os
import time
from typing import Dict, Any, Optional
import geoip2.database
import requests

RAW_LOG_FILE = "honeypot_events.jsonl"
ENRICHED_LOG_FILE = "enriched_events.jsonl"
GEOIP_CITY_DB = "data/GeoLite2-City.mmdb"
GEOIP_ASN_DB = "data/GeoLite2-ASN.mmdb"

# Replace with your actual key or load via os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "e537b784743341c80a1adc8d291d1a423efed75ba5938d1a70f351b685d8371a0dc7578ede83a437")

# In-memory IP cache to save API quota and accelerate processing
ip_cache: Dict[str, Dict[str, Any]] = {}


def is_public_ip(ip_str: str) -> bool:
    """Filters out private (RFC 1918), loopback, and link-local addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local)
    except ValueError:
        return False


def get_geoip_data(ip_str: str, city_reader, asn_reader) -> Dict[str, Any]:
    """Queries offline MaxMind MMDB files for location and ASN data."""
    geo_data = {
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": "Unknown"
    }

    if not is_public_ip(ip_str):
        geo_data["country"] = "Internal / Private"
        return geo_data

    # City & Country Lookup
    if city_reader:
        try:
            resp = city_reader.city(ip_str)
            geo_data["country"] = resp.country.name or "Unknown"
            geo_data["country_code"] = resp.country.iso_code or "XX"
            geo_data["city"] = resp.city.name or "Unknown"
            geo_data["latitude"] = resp.location.latitude
            geo_data["longitude"] = resp.location.longitude
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[-] GeoIP City error for {ip_str}: {e}")

    # ASN Lookup
    if asn_reader:
        try:
            resp = asn_reader.asn(ip_str)
            geo_data["asn"] = resp.autonomous_system_number
            geo_data["org"] = resp.autonomous_system_organization or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            pass
        except Exception as e:
            print(f"[-] GeoIP ASN error for {ip_str}: {e}")

    return geo_data


def get_abuseipdb_data(ip_str: str) -> Dict[str, Any]:
    """Queries AbuseIPDB REST API for threat score and report history."""
    default_abuse = {
        "abuse_score": 0,
        "total_reports": 0,
        "is_whitelisted": False,
        "last_reported_at": None
    }

    if not is_public_ip(ip_str) or not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_API_KEY_HERE":
        return default_abuse

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_str,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported_at": data.get("lastReportedAt")
            }
        elif response.status_code == 429:
            print("[-] AbuseIPDB rate limit exceeded.")
        else:
            print(f"[-] AbuseIPDB returned status {response.status_code}")
    except requests.RequestException as e:
        print(f"[-] AbuseIPDB connection failed for {ip_str}: {e}")

    return default_abuse


def enrich_event(event: Dict[str, Any], city_reader, asn_reader) -> Dict[str, Any]:
    """Combines raw event metadata with cached or fetched threat intelligence."""
    src_ip = event.get("src_ip", "")
    
    if src_ip not in ip_cache:
        geo = get_geoip_data(src_ip, city_reader, asn_reader)
        abuse = get_abuseipdb_data(src_ip)
        ip_cache[src_ip] = {**geo, **abuse}
        # Respect API rate limits
        time.sleep(0.1)

    # Attach threat intel directly under an 'intelligence' block
    enriched_event = dict(event)
    enriched_event["intelligence"] = ip_cache[src_ip]
    return enriched_event


def run_pipeline():
    if not os.path.exists(RAW_LOG_FILE):
        print(f"[-] Source log {RAW_LOG_FILE} not found. Generate logs first.")
        return

    # Initialize MMDB readers safely
    city_reader = None
    asn_reader = None

    if os.path.exists(GEOIP_CITY_DB):
        city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
    else:
        print(f"[!] Warning: {GEOIP_CITY_DB} not found. Skipping GeoIP city lookups.")

    if os.path.exists(GEOIP_ASN_DB):
        asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
    else:
        print(f"[!] Warning: {GEOIP_ASN_DB} not found. Skipping GeoIP ASN lookups.")

    count = 0
    with open(RAW_LOG_FILE, "r", encoding="utf-8") as infile, \
         open(ENRICHED_LOG_FILE, "w", encoding="utf-8") as outfile:
        
        for line in infile:
            if not line.strip():
                continue
            raw_event = json.loads(line)
            enriched = enrich_event(raw_event, city_reader, asn_reader)
            outfile.write(json.dumps(enriched) + "\n")
            count += 1

    if city_reader:
        city_reader.close()
    if asn_reader:
        asn_reader.close()

    print(f"[+] Successfully enriched {count} events -> {ENRICHED_LOG_FILE}")


if __name__ == "__main__":
    run_pipeline()