import json
import time

import requests

GREEN = "\033[0;32m"
BLUE = "\033[0;34m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"

WAF_URL = "http://localhost:5000"
VULN_URL = "http://localhost:5001"
IDS_URL = "http://localhost:5002"
INTEGRATION_URL = "http://localhost:8000"
SIEM_URL = "http://localhost:3000"


def check_services():
    print(f"{BLUE}🔍 Checking if services are running...{NC}\n")
    for name, url in [
        ("WAF", WAF_URL),
        ("Vuln Scanner", VULN_URL),
        ("IDS", IDS_URL),
        ("Integration", INTEGRATION_URL),
        ("SIEM", SIEM_URL),
    ]:
        try:
            resp = requests.get(f"{url}/health", timeout=2)
            if resp.ok:
                print(f"{GREEN}✓{NC} {name} is running")
            else:
                print(f"{RED}✗{NC} {name} is NOT running")
        except requests.RequestException:
            print(f"{RED}✗{NC} {name} is NOT running")
    print()


def trigger_service(name, url, endpoint, count=1):
    # Each service picks its alert type at random, so call it multiple times
    # to have a good chance of triggering every alert variant it knows about.
    for i in range(count):
        print(f"{YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
        print(f"{BLUE}🚨 Triggering {name} ({i + 1}/{count}){NC}")
        print(f"{YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}\n")

        try:
            resp = requests.get(f"{url}{endpoint}", timeout=5)
            try:
                print(json.dumps(resp.json(), indent=2))
            except ValueError:
                print(resp.text)
        except requests.RequestException as exc:
            print(f"{RED}Request failed: {exc}{NC}")

        print()
        time.sleep(2)


def print_json(title, url):
    print(f"{YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{BLUE}{title}{NC}")
    print(f"{YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}\n")

    try:
        resp = requests.get(url, timeout=5)
        try:
            print(json.dumps(resp.json(), indent=2))
        except ValueError:
            print(resp.text)
    except requests.RequestException as exc:
        print(f"{RED}Request failed: {exc}{NC}")


def main():
    print(f"{BLUE}🔒 Security Alert Integration Demo{NC}\n")

    check_services()

    print(f"{BLUE}📡 TRIGGERING SECURITY ALERTS...{NC}\n")
    # Each service randomly picks from 5 alert/finding types per call, so
    # trigger it 5 times to cover the full range of alerts it can produce.
    trigger_service("WAF (SQL Injection)", WAF_URL, "/trigger-alert", count=5)
    trigger_service("Vulnerability Scanner (CVE)", VULN_URL, "/trigger-scan", count=5)
    trigger_service("IDS (Intrusion)", IDS_URL, "/trigger-detection", count=5)

    print_json("📊 SIEM EVENT AGGREGATION", f"{SIEM_URL}/api/events")
    print()
    print_json("🛡️  SECURITY DASHBOARD", f"{SIEM_URL}/api/dashboard")

    print(f"\n{GREEN}✅ Demo Complete!{NC}\n")


if __name__ == "__main__":
    main()
