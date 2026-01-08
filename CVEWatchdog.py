import argparse
import subprocess
import sys
import re
import requests
from urllib.parse import quote

CVSS_LEVELS = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 0.1
}

# ANSI color codes
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    BLACK = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Software:
    def __init__(self, name, version):
        self.name = name
        self.version = version

def get_installed_software():
    """Scan installed software packages on Linux"""
    print(f"{Colors.CYAN}📦 Scanning installed software...{Colors.RESET}")
    
    software = []
    ignored = 0
    
    # Try different package managers
    package_managers = [
        ("dpkg", ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]),
        ("rpm", ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"]),
        ("pacman", ["pacman", "-Q"]),
        ("apk", ["apk", "info", "-v"])
    ]
    
    for pm_name, command in package_managers:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    if not line.strip():
                        continue
                    
                    parts = line.split('\t') if '\t' in line else line.split()
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        version = parts[1].strip()
                        
                        # Remove architecture suffix (e.g., :amd64)
                        if ':' in name:
                            name = name.split(':')[0]
                        
                        # Remove epoch from version (e.g., 1:2.3.4)
                        if ':' in version:
                            version = version.split(':', 1)[1]
                        
                        # Remove release suffix (e.g., -1ubuntu1)
                        version = version.split('-')[0]
                        
                        # Ignore kernel and core system packages
                        ignore_patterns = []
                        
                        if any(pattern in name.lower() for pattern in ignore_patterns):
                            ignored += 1
                            continue
                        
                        software.append(Software(name=name, version=version))
                
                print(f"{Colors.GREEN}✅ Found {len(software)} packages using {pm_name} "
                      f"(ignoring {ignored} system packages){Colors.RESET}")
                return software, ignored
                
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            continue
    
    print(f"{Colors.RED}❌ No supported package manager found (dpkg, rpm, pacman, apk){Colors.RESET}")
    sys.exit(1)

def get_product_name_variations(software_name, version):
    """Generate name variations for API matching (optimized for Linux packages)"""
    tier1, tier2 = [], []
    all_variations = set()
    
    def add_variation(value, tier_list):
        if value and len(value.strip()) > 1 and not value.isdigit():
            if value not in all_variations:
                all_variations.add(value)
                tier_list.append(value)
    
    # TIER 1: Exact package name
    add_variation(software_name, tier1)
    
    # TIER 2: Common transformations
    # Remove trailing numbers (e.g., libssl3 -> libssl)
    base_name = re.sub(r'\d+\Z', '', software_name)
    if base_name != software_name:
        add_variation(base_name, tier2)
    
    # Remove common suffixes
    for suffix in ['-dev', '-doc', '-common', '-data', '-bin', '-tools', '-utils']:
        if software_name.endswith(suffix):
            cleaned = software_name[:-len(suffix)]
            add_variation(cleaned, tier2)
    
    return {
        'tier1': tier1,
        'tier2': tier2
    }

def get_cves_from_api(api_url, software_name, version, debug=False):
    """Query the CVE API for vulnerabilities"""
    variations = get_product_name_variations(software_name, version)
    
    if debug:
        print(f"{Colors.GRAY}DEBUG - Name variations for '{software_name}':{Colors.RESET}")
        for tier in ['tier1', 'tier2']:
            if variations[tier]:
                print(f"{Colors.GRAY}  {tier}:{Colors.RESET}")
                for var in variations[tier]:
                    print(f"{Colors.GRAY}    → {var}{Colors.RESET}")
    
    for tier in ['tier1', 'tier2']:
        for name in variations[tier]:
            try:
                uri = f"{api_url}/api/cve/search?software={quote(name)}"
                if version:
                    uri += f"&version={quote(version)}"
                
                response = requests.get(uri, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('results'):
                        if debug:
                            print(f"{Colors.GRAY}✨ Matched API using: '{name}' (from {tier}){Colors.RESET}")
                        return {
                            'results': data['results'],
                            'matched_variation': name,
                            'matched_tier': tier
                        }
            except (requests.RequestException, KeyError):
                continue
    
    return None

def get_cvss_severity(score):
    """Get severity level from CVSS score"""
    if score is None:
        return "Unknown"
    if score >= CVSS_LEVELS["Critical"]:
        return "Critical"
    elif score >= CVSS_LEVELS["High"]:
        return "High"
    elif score >= CVSS_LEVELS["Medium"]:
        return "Medium"
    elif score >= CVSS_LEVELS["Low"]:
        return "Low"
    return "None"

def format_cve_table(cves):
    """Format CVE data as a table"""
    if not cves:
        return
    
    print(f"\n{'CVE ID':<20} {'Severity':<12} {'CVSS':<8} {'Version':<15} {'Published':<12} {'Description':<50}")
    print("─" * 120)
    
    for cve in cves:
        severity = get_cvss_severity(cve.get('cvss_score'))
        cvss_str = f"{cve.get('cvss_score', 0):.1f}" if cve.get('cvss_score') else "N/A"
        published = cve.get('published', '').split('T')[0]
        description = cve.get('description', '')
        
        if len(description) > 50:
            description = description[:47] + "..."
        
        # Color code severity
        severity_color = Colors.RESET
        if severity == "Critical":
            severity_color = Colors.BLACK
        elif severity == "High":
            severity_color = Colors.RED
        elif severity == "Medium":
            severity_color = Colors.YELLOW
        elif severity == "Low":
            severity_color = Colors.GREEN
        
        print(f"{cve.get('cve_id', ''):<20} {severity_color}{severity:<12}{Colors.RESET} "
              f"{cvss_str:<8} {cve.get('version', ''):<15} {published:<12} {description:<50}")

def main():
    parser = argparse.ArgumentParser(description='CVEWatchdog - Linux Vulnerability Scanner')
    parser.add_argument('api_url', help='CVE API URL (e.g., http://localhost:5000)')
    parser.add_argument('--wildcards', action='store_true', help='Include wildcard version matches')
    parser.add_argument('--debug', action='store_true', help='Enable debug output for matching')
    
    args = parser.parse_args()
    
    print(f"\n{Colors.CYAN}{'═' * 45}")
    print("                CVEWatchdog                ")
    print(f"{'═' * 45}{Colors.RESET}\n")
    
    # Check API connectivity
    print(f"{Colors.CYAN}🌐 Checking API connectivity...{Colors.RESET}")
    try:
        response = requests.get(f"{args.api_url}/health", timeout=5)
        health = response.json()
        print(f"{Colors.GREEN}✅ API connected - {health.get('cves_indexed', 0)} CVEs indexed{Colors.RESET}\n")
    except requests.RequestException as e:
        print(f"{Colors.RED}❌ Cannot connect to API at {args.api_url}{Colors.RESET}")
        sys.exit(1)
    
    # Get installed software
    software_list, ignored_count = get_installed_software()
    
    print(f"\n{Colors.CYAN}🔍 Searching for vulnerabilities...{Colors.RESET}\n")
    
    software_with_cves = []
    all_cves = []
    api_matches = 0
    
    for app in software_list:
        cve_result = get_cves_from_api(args.api_url, app.name, app.version, args.debug)
        cves = None
        
        if cve_result:
            cves = cve_result['results']
            api_matches += 1
        
        # Filter out wildcard versions if not requested
        if not args.wildcards and cves:
            cves = [cve for cve in cves if cve.get('version') != '*']
        
        if cves:
            print(f"{Colors.YELLOW}⚠️  {app.name} ({app.version}) - {len(cves)} CVE(s) detected{Colors.RESET}")
            software_with_cves.append({
                'name': app.name,
                'version': app.version,
                'cves': cves
            })
            all_cves.extend(cves)
        else:
            if args.debug:
                print(f"{Colors.GREEN}✓ {app.name} ({app.version}) - No CVEs detected{Colors.RESET}")
    
    # Print vulnerability report
    print(f"\n{'═' * 45}")
    print("            VULNERABILITY REPORT")
    print(f"{'═' * 45}\n")
    
    if not software_with_cves:
        print(f"{Colors.GREEN}✅ No vulnerabilities detected!{Colors.RESET}")
    else:
        for app in software_with_cves:
            print(f"\n{Colors.MAGENTA}📌 {app['name']} - Version: {app['version']}{Colors.RESET}")
            format_cve_table(app['cves'])
    
    # Print summary
    print(f"\n{'═' * 45}")
    print("               SUMMARY")
    print(f"{'═' * 45}\n")
    
    total_cves = len(all_cves)
    critical_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Critical")
    high_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "High")
    medium_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Medium")
    low_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Low")
    unknown_count = sum(1 for cve in all_cves if get_cvss_severity(cve.get('cvss_score')) == "Unknown")
    
    print(f"Software scanned        : {len(software_list)}")
    print(f"Software ignored        : {ignored_count}")
    print(f"API matches found       : {api_matches}")
    print()
    print(f"{Colors.CYAN}Total CVEs found        : {total_cves}{Colors.RESET}")
    print(f"{Colors.BLACK}Critical vulnerabilities: {critical_count}{Colors.RESET}")
    print(f"{Colors.RED}High vulnerabilities    : {high_count}{Colors.RESET}")
    print(f"{Colors.YELLOW}Medium vulnerabilities  : {medium_count}{Colors.RESET}")
    print(f"{Colors.GREEN}Low vulnerabilities     : {low_count}{Colors.RESET}")
    
    if unknown_count > 0:
        print(f"{Colors.GRAY}Unknown vulnerabilities : {unknown_count}{Colors.RESET}")
    
    print()
    
    # Risk assessment
    risk_level = "🟢 LOW RISK"
    risk_color = Colors.GREEN
    
    if critical_count > 0:
        risk_level = "⚫️ CRITICAL RISK"
        risk_color = Colors.BLACK
    elif high_count > 3:
        risk_level = "🔴 HIGH RISK"
        risk_color = Colors.RED
    elif high_count > 0:
        risk_level = "🟠 MEDIUM RISK"
        risk_color = Colors.YELLOW
    
    print(f"Overall Risk Assessment : {risk_color}{risk_level}{Colors.RESET}")
    print()

if __name__ == "__main__":
    main()
