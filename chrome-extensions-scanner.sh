#!/bin/bash

# Author: Latheesan Kanesamoorthy (with assistance from Claude 3.7 Sonnet)
# Purpose: Antivirus deep scanner for Chrome extensions on Linux
# Scans for requests to suspicious/malicious external URLs, obfuscated code, and unusual permissions

set -o pipefail  # Ensures pipe failures are caught

# ANSI color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if required tools are installed
for tool in jq grep sed awk find; do
    if ! command -v $tool &> /dev/null; then
        echo -e "${RED}${BOLD}Error:${NC} $tool is not installed. Please install it to run this script."
        exit 1
    fi
done

# Define the Chrome user data directory
chrome_dir=~/.config/google-chrome

# Check if Chrome user data directory exists
if [ ! -d "$chrome_dir" ]; then
    echo -e "${RED}${BOLD}Chrome user data directory not found at $chrome_dir${NC}"
    echo "Ensure Chrome is installed and has been used."
    exit 1
fi

# Whitelist of safe domains (add more as needed)
safe_domains=(
    "google.com"
    "gstatic.com"
    "googleapis.com"
    "chrome.com"
    "chromium.org"
    "googlesource.com"
    "github.com"
    "cloudflare.com"
    "jsdelivr.net"
    "jquery.com"
    "unpkg.com"
    "cdnjs.cloudflare.com"
)

# Suspicious TLDs (commonly associated with malicious activity)
suspicious_tlds=(
    "ru" "cn" "top" "xyz" "club" "info" "biz" "cc" "tk" "ml" "ga" "cf" "gq"
)

# High-risk permissions that extensions might request
high_risk_permissions=(
    "tabs"
    "webRequest"
    "webRequestBlocking"
    "cookies"
    "history"
    "clipboardRead"
    "activeTab"
    "downloads"
    "bookmarks"
    "storage"
    "browserSettings"
    "<all_urls>"
)

# Patterns indicative of obfuscation or malicious code
suspicious_patterns=(
    "eval\\s*\\("
    "Function\\s*\\(\\s*['\\\"]return"
    "String\\.fromCharCode"
    "unescape\\s*\\("
    "decodeURIComponent\\s*\\("
    "\\\\u00[0-9a-f]{2}"
    "\\\\x[0-9a-f]{2}"
    "atob\\s*\\("
    "btoa\\s*\\("
    "crypto\\.subtle"
    "\\.replace\\(/[^/]+/g,"
)

# Function to check if a URL is safe (ignores localhost, private networks, Bogon IPs)
is_safe_url() {
    local url="$1"

    # Extract host from URL, handling different formats
    # Enhanced to handle localhost URLs with paths/ports better
    host=$(echo "$url" | sed -E 's|^https?://([^/:]+)[:/].*|\1|')

    # Ignore localhost in all forms
    if [[ "$host" =~ ^(localhost|127\.0\.0\.1|::1|0\.0\.0\.0)$ ]]; then
        return 0 # Safe
    fi

    # Check for IPv4 addresses
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        IFS='.' read -r -a octets <<< "$host"
        local o1=${octets[0]}
        local o2=${octets[1]}
        local o3=${octets[2]}
        local o4=${octets[3]}

        # Ignore private IPv4 ranges
        if [[ "$o1" -eq 10 ]]; then
            return 0 # Private (10.0.0.0/8)
        elif [[ "$o1" -eq 172 ]] && [[ "$o2" -ge 16 ]] && [[ "$o2" -le 31 ]]; then
            return 0 # Private (172.16.0.0/12)
        elif [[ "$o1" -eq 192 ]] && [[ "$o2" -eq 168 ]]; then
            return 0 # Private (192.168.0.0/16)
        fi

        # Ignore Bogon IPv4 ranges
        if [[ "$o1" -eq 127 ]]; then
            return 0 # Loopback (127.0.0.0/8)
        elif [[ "$o1" -eq 169 ]] && [[ "$o2" -eq 254 ]]; then
            return 0 # Link-local (169.254.0.0/16)
        elif [[ "$o1" -ge 224 ]] && [[ "$o1" -le 239 ]]; then
            return 0 # Multicast (224.0.0.0/4)
        elif [[ "$o1" -eq 0 ]]; then
            return 0 # Reserved (0.0.0.0/8)
        elif [[ "$o1" -ge 240 ]]; then
            return 0 # Reserved (240.0.0.0/4)
        fi
    fi

    # Check for IPv6 addresses (e.g., [::1], [fe80::1])
    if [[ "$host" =~ ^\[.*\]$ ]]; then
        local ipv6=$(echo "$host" | sed 's/^\[\(.*\)\]$/\1/')
        # Ignore loopback
        if [[ "$ipv6" == "::1" ]]; then
            return 0 # Safe
        fi
        # Ignore link-local (fe80::/10)
        if [[ "$ipv6" =~ ^fe[89ab].* ]]; then
            return 0 # Safe
        fi
        # Ignore unique local (fc00::/7)
        if [[ "$ipv6" =~ ^f[c-d].* ]]; then
            return 0 # Safe
        fi
        # Ignore multicast (ff00::/8)
        if [[ "$ipv6" =~ ^ff.* ]]; then
            return 0 # Safe
        fi
    fi

    # Extract domain from host
    local domain=$(echo "$host" | grep -oE "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -n 1)

    # If no valid domain was extracted (could be an IP), use original host
    if [[ -z "$domain" ]]; then
        domain="$host"
    fi

    # Extract TLD, safely handling domains that might not have a proper TLD format
    local tld=""
    if [[ "$domain" =~ \. ]]; then
        tld=$(echo "$domain" | awk -F'.' '{print $NF}')
    fi

    # Check if domain is in whitelist
    for safe in "${safe_domains[@]}"; do
        if [[ "$domain" == *"$safe" ]]; then
            return 0 # Safe
        fi
    done

    # Check for suspicious patterns
    # 1. Raw IP addresses (if not private/Bogon, consider suspicious)
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        return 1 # Suspicious
    fi
    # 2. Non-standard ports (e.g., :8080)
    if echo "$url" | grep -qE ":[0-9]{4,5}"; then
        return 1 # Suspicious
    fi
    # 3. Suspicious TLDs
    if [[ -n "$tld" ]]; then
        for suspicious in "${suspicious_tlds[@]}"; do
            if [[ "$tld" == "$suspicious" ]]; then
                return 1 # Suspicious
            fi
        done
    fi

    # Default: Assume safe
    return 0
}

# Function to check for obfuscated code
check_obfuscation() {
    local file="$1"
    local results=""

    # Check if file is too large (>5MB)
    # FIX: Use stat command instead of wc for more reliable file size detection
    if [[ -f "$file" ]]; then
        # Use stat to get file size - works on both Linux and macOS
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS version
            local file_size=$(stat -f%z "$file")
        else
            # Linux version
            local file_size=$(stat -c%s "$file")
        fi

        if [[ $file_size -gt 5000000 ]]; then
            results="${results}    ${YELLOW}⚠ Large file detected ($(( file_size / 1024 / 1024 )) MB) - potentially obfuscated${NC}\n"

            # Only check the first 1MB of large files
            head -c 1000000 "$file" > "/tmp/chrome_scanner_temp.js"
            file="/tmp/chrome_scanner_temp.js"
        fi
    else
        echo -e "${YELLOW}Warning: File not found - $file${NC}"
        return 1
    fi

    for pattern in "${suspicious_patterns[@]}"; do
        if grep -q -E "$pattern" "$file" 2>/dev/null; then
            match=$(grep -E "$pattern" "$file" 2>/dev/null | head -n 1 | tr -d '\n' | cut -c 1-60)
            if [[ -n "$match" ]]; then
                results="${results}    ${YELLOW}⚠ Suspicious pattern: ${pattern} (e.g., '${match}...')${NC}\n"
            fi
        fi
    done

    # Check for very long lines (potential minified/obfuscated code)
    local long_line_count=$(grep -c '.\{500,\}' "$file" 2>/dev/null || echo "0")
    long_line_count=$(echo "$long_line_count" | tr -d '[:space:]')
    if [[ $long_line_count -gt 0 ]]; then
        results="${results}    ${YELLOW}⚠ Contains $long_line_count extremely long lines (>500 chars) - potential obfuscation${NC}\n"
    fi

    # Clean up temp file if created
    if [[ -f "/tmp/chrome_scanner_temp.js" ]]; then
        rm "/tmp/chrome_scanner_temp.js"
    fi

    echo -e "$results"
}

# Function to check for URL construction in JavaScript
check_url_construction() {
    local file="$1"
    local results=""
    local match=""

    # FIX: Escape the quotes properly in the regex patterns
    # Check for URL concatenation
    if grep -q -E '("|'"'"'|`)(https?:)?\/\/['"'"'"`+ ]' "$file" 2>/dev/null; then
        match=$(grep -E '("|'"'"'|`)(https?:)?\/\/['"'"'"`+ ]' "$file" 2>/dev/null | head -n 1 | tr -d '\n' | cut -c 1-60)
        if [[ -n "$match" ]]; then
            results="${results}    ${YELLOW}⚠ URL concatenation detected: '${match}...'${NC}\n"
        fi
    fi

    # Check for dynamic protocol (could be used to bypass filters)
    if grep -q -E "location\.protocol.*\+" "$file" 2>/dev/null; then
        match=$(grep -E "location\.protocol.*\+" "$file" 2>/dev/null | head -n 1 | tr -d '\n' | cut -c 1-60)
        if [[ -n "$match" ]]; then
            results="${results}    ${YELLOW}⚠ Dynamic protocol usage: '${match}...'${NC}\n"
        fi
    fi

    # Check for fetch/xhr calls with variable URLs
    if grep -q -E "(fetch|XMLHttpRequest|\.ajax|\.get|\.post)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*" "$file" 2>/dev/null; then
        match=$(grep -E "(fetch|XMLHttpRequest|\.ajax|\.get|\.post)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*" "$file" 2>/dev/null | head -n 1 | tr -d '\n' | cut -c 1-60)
        if [[ -n "$match" ]]; then
            results="${results}    ${YELLOW}⚠ Dynamic URL in network request: '${match}...'${NC}\n"
        fi
    fi

    echo -e "$results"
}

# Function to analyze content security policy
analyze_csp() {
    local manifest_file="$1"
    local results=""

    if [[ -f "$manifest_file" ]]; then
        # Check if CSP exists (handle both v2 and v3 manifest formats)
        local csp=$(jq -r '.content_security_policy // .content_security_policy_v3.extension_pages // ""' "$manifest_file" 2>/dev/null)
        if [[ -z "$csp" ]]; then
            results="${results}    ${YELLOW}⚠ No Content Security Policy defined${NC}\n"
        else
            # Check for unsafe CSP directives
            if [[ "$csp" == *"unsafe-eval"* ]]; then
                results="${results}    ${RED}❌ Unsafe CSP: Allows eval() (unsafe-eval)${NC}\n"
            fi
            if [[ "$csp" == *"unsafe-inline"* ]]; then
                results="${results}    ${RED}❌ Unsafe CSP: Allows inline scripts (unsafe-inline)${NC}\n"
            fi
            if [[ "$csp" == *"*"* ]]; then
                results="${results}    ${RED}❌ Unsafe CSP: Contains wildcard (*) permissions${NC}\n"
            fi
            if [[ "$csp" == *"data:"* ]]; then
                results="${results}    ${RED}❌ Unsafe CSP: Allows data: URIs${NC}\n"
            fi
            if [[ "$csp" == *"blob:"* ]]; then
                results="${results}    ${YELLOW}⚠ Suspicious CSP: Allows blob: URIs${NC}\n"
            fi
        fi
    fi

    echo -e "$results"
}

# Function to analyze permissions
analyze_permissions() {
    local manifest_file="$1"
    local results=""

    if [[ -f "$manifest_file" ]]; then
        # Handle permissions as either array or object (jq's type is null if not present)
        local perm_type=$(jq -r 'if .permissions | type == "array" then "array" elif .permissions | type == "object" then "object" else "none" end' "$manifest_file" 2>/dev/null)

        if [[ "$perm_type" == "array" ]]; then
            # Process array-style permissions
            local permissions=$(jq -r '.permissions[]? // ""' "$manifest_file" 2>/dev/null)

            if [[ -n "$permissions" ]]; then
                while IFS= read -r perm; do
                    for high_risk in "${high_risk_permissions[@]}"; do
                        if [[ "$perm" == "$high_risk" ]]; then
                            results="${results}    ${YELLOW}⚠ High-risk permission: ${BOLD}$perm${NC}\n"
                            break
                        fi
                    done
                done <<< "$permissions"
            fi
        elif [[ "$perm_type" == "object" ]]; then
            # Process object-style permissions (manifest v3)
            local obj_permissions=$(jq -r '.permissions | keys[]' "$manifest_file" 2>/dev/null)

            if [[ -n "$obj_permissions" ]]; then
                while IFS= read -r perm; do
                    for high_risk in "${high_risk_permissions[@]}"; do
                        if [[ "$perm" == "$high_risk" ]]; then
                            results="${results}    ${YELLOW}⚠ High-risk permission: ${BOLD}$perm${NC}\n"
                            break
                        fi
                    done
                done <<< "$obj_permissions"
            fi
        fi

        # Check for host permissions
        local host_permissions=$(jq -r '.host_permissions[]? // ""' "$manifest_file" 2>/dev/null)
        if [[ -n "$host_permissions" ]]; then
            while IFS= read -r host; do
                if [[ "$host" == "<all_urls>" || "$host" == "*://*/*" ]]; then
                    results="${results}    ${RED}❌ Requests access to all URLs: ${BOLD}$host${NC}\n"
                fi
            done <<< "$host_permissions"
        fi

        # Check for optional_permissions
        local optional_permissions=$(jq -r '.optional_permissions[]? // ""' "$manifest_file" 2>/dev/null)
        if [[ -n "$optional_permissions" ]]; then
            while IFS= read -r perm; do
                for high_risk in "${high_risk_permissions[@]}"; do
                    if [[ "$perm" == "$high_risk" ]]; then
                        results="${results}    ${YELLOW}⚠ Optional high-risk permission: ${BOLD}$perm${NC}\n"
                        break
                    fi
                done
            done <<< "$optional_permissions"
        fi
    fi

    echo -e "$results"
}

# Function to check for other suspicious files
check_suspicious_files() {
    local extension_dir="$1"
    local results=""

    # Check for hidden files
    local hidden_files=$(find "$extension_dir" -name ".*" -type f 2>/dev/null | wc -l)
    if [[ $hidden_files -gt 0 ]]; then
        results="${results}    ${YELLOW}⚠ Contains $hidden_files hidden files${NC}\n"
    fi

    # Check for native binaries
    local binaries=$(find "$extension_dir" -type f -executable -o -name "*.so" -o -name "*.dll" -o -name "*.exe" -o -name "*.bin" 2>/dev/null | wc -l)
    if [[ $binaries -gt 0 ]]; then
        results="${results}    ${RED}❌ Contains $binaries native binary files${NC}\n"
    fi

    # Check for WebAssembly modules
    local wasm_modules=$(find "$extension_dir" -name "*.wasm" 2>/dev/null | wc -l)
    if [[ $wasm_modules -gt 0 ]]; then
        results="${results}    ${YELLOW}⚠ Contains $wasm_modules WebAssembly modules${NC}\n"
    fi

    echo -e "$results"
}

# Create arrays to track high risk extensions for summary
declare -a high_risk_extensions
declare -a medium_risk_extensions

echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║              Chrome Extension Security Scanner               ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Iterate through each profile directory
for profile_dir in "$chrome_dir"/*; do
    if [[ -d "$profile_dir/Extensions" ]]; then
        profile_name=$(basename "$profile_dir")
        echo -e "${BOLD}${PURPLE}🔍 Scanning profile:${NC} ${BOLD}$profile_name${NC}"
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        found=0

        # Iterate through each extension directory
        for extension_dir in "$profile_dir/Extensions"/*; do
            if [[ -d "$extension_dir" ]]; then
                extension_id=$(basename "$extension_dir")

                # Find the latest version directory (handling version format properly)
                if ! latest_version_dir=$(find "$extension_dir" -maxdepth 1 -type d | grep -v "^$extension_dir\$" | sort -V | tail -n 1); then
                    continue
                fi

                if [[ -z "$latest_version_dir" || ! -d "$latest_version_dir" ]]; then
                    continue
                fi

                manifest_file="$latest_version_dir/manifest.json"
                if [[ -f "$manifest_file" ]]; then
                    # Get extension info (handling potential jq errors)
                    extension_name=$(jq -r '.name | if type=="string" then . else "" end' "$manifest_file" 2>/dev/null)
                    # Handle extension names that might be in _locales
                    if [[ "$extension_name" == "__MSG_"* ]]; then
                        # Extract the message name
                        msg_name=$(echo "$extension_name" | sed -E 's/__MSG_(.*)__/\1/')
                        # Try to find it in default locale
                        default_locale=$(jq -r '.default_locale // "en"' "$manifest_file" 2>/dev/null)
                        locale_file="$latest_version_dir/_locales/$default_locale/messages.json"
                        if [[ -f "$locale_file" ]]; then
                            extension_name=$(jq -r ".[\"$msg_name\"].message // \"Unknown\"" "$locale_file" 2>/dev/null)
                        else
                            # Try to find any locale file
                            first_locale_file=$(find "$latest_version_dir/_locales" -name "messages.json" | head -1)
                            if [[ -f "$first_locale_file" ]]; then
                                extension_name=$(jq -r ".[\"$msg_name\"].message // \"Unknown\"" "$first_locale_file" 2>/dev/null)
                            else
                                extension_name="Unknown (ID: $extension_id)"
                            fi
                        fi
                    fi

                    # If name is still empty, use ID
                    if [[ -z "$extension_name" ]]; then
                        extension_name="Unknown (ID: $extension_id)"
                    fi

                    extension_version=$(jq -r '.version // "unknown"' "$manifest_file" 2>/dev/null)

                    # Track suspicious findings for this extension
                    suspicious_urls=""
                    obfuscation_findings=""
                    constructed_urls=""
                    csp_issues=""
                    permission_issues=""
                    suspicious_files=""

                    # 1. Scan for direct URLs in JavaScript files - with better error handling
                    while IFS=':' read -r file_path line rest || [[ -n "$file_path" ]]; do
                        # Check if the line is valid and has content
                        if [[ -n "$rest" ]]; then
                            # Extract actual URL from the line
                            url=$(echo "$rest" | grep -o -E 'https?://[^"'\''`\) ]+' | head -n 1)
                            if [[ -n "$url" ]]; then
                                # Compare with full path to avoid confusion in output
                                full_path="$file_path"
                                if ! is_safe_url "$url"; then
                                    # Convert absolute path to relative path for display
                                    rel_path=${full_path#"$latest_version_dir/"}
                                    suspicious_urls="${suspicious_urls}    ${YELLOW}⚠ $url ${NC}(in ${CYAN}$rel_path:$line${NC})\n"
                                fi
                            fi
                        fi
                    done < <(grep -r --include="*.js" -n -o -E "https?://[^\"'\`\) ]+" "$latest_version_dir" 2>/dev/null || echo "")

                    # 2. Check for obfuscated code - safely find JS files
                    while IFS= read -r js_file || [[ -n "$js_file" ]]; do
                        if [[ -f "$js_file" ]]; then
                            obfuscation_result=$(check_obfuscation "$js_file")
                            if [[ -n "$obfuscation_result" ]]; then
                                file_rel_path=${js_file#"$latest_version_dir/"}
                                obfuscation_findings="${obfuscation_findings}    ${CYAN}File:${NC} ${BOLD}$file_rel_path${NC}\n$obfuscation_result"
                            fi

                            # 3. Check for URL construction
                            url_construction_result=$(check_url_construction "$js_file")
                            if [[ -n "$url_construction_result" ]]; then
                                file_rel_path=${js_file#"$latest_version_dir/"}
                                constructed_urls="${constructed_urls}    ${CYAN}File:${NC} ${BOLD}$file_rel_path${NC}\n$url_construction_result"
                            fi
                        fi
                    done < <(find "$latest_version_dir" -name "*.js" -type f 2>/dev/null || echo "")

                    # 4. Analyze Content Security Policy
                    csp_issues=$(analyze_csp "$manifest_file")

                    # 5. Analyze permissions
                    permission_issues=$(analyze_permissions "$manifest_file")

                    # 6. Check for suspicious files
                    suspicious_files=$(check_suspicious_files "$latest_version_dir")

                    # Report findings if any
                    if [[ -n "$suspicious_urls" ]] || [[ -n "$obfuscation_findings" ]] || [[ -n "$constructed_urls" ]] || \
                       [[ -n "$csp_issues" ]] || [[ -n "$permission_issues" ]] || [[ -n "$suspicious_files" ]]; then
                        found=1
                        echo -e "  ${BOLD}${BLUE}⬢ Extension:${NC} ${BOLD}$extension_name${NC}"
                        echo -e "  ${BLUE}⬢ ID:${NC} $extension_id"
                        echo -e "  ${BLUE}⬢ Version:${NC} $extension_version"
                        echo ""

                        if [[ -n "$suspicious_urls" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Suspicious URLs:${NC}"
                            echo -e "$suspicious_urls"
                            echo ""
                        fi

                        if [[ -n "$obfuscation_findings" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Potential Code Obfuscation:${NC}"
                            echo -e "$obfuscation_findings"
                            echo ""
                        fi

                        if [[ -n "$constructed_urls" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Dynamic URL Construction (may bypass filters):${NC}"
                            echo -e "$constructed_urls"
                            echo ""
                        fi

                        if [[ -n "$csp_issues" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Content Security Policy Issues:${NC}"
                            echo -e "$csp_issues"
                            echo ""
                        fi

                        if [[ -n "$permission_issues" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Permission Concerns:${NC}"
                            echo -e "$permission_issues"
                            echo ""
                        fi

                        if [[ -n "$suspicious_files" ]]; then
                            echo -e "  ${RED}${BOLD}⚠ Suspicious Files:${NC}"
                            echo -e "$suspicious_files"
                            echo ""
                        fi

                        # Calculate and display a risk score
                        risk_score=0
                        [[ -n "$suspicious_urls" ]] && ((risk_score+=3))
                        [[ -n "$obfuscation_findings" ]] && ((risk_score+=3))
                        [[ -n "$constructed_urls" ]] && ((risk_score+=2))
                        [[ -n "$csp_issues" ]] && ((risk_score+=2))
                        [[ -n "$permission_issues" ]] && ((risk_score+=2))
                        [[ -n "$suspicious_files" ]] && ((risk_score+=2))

                        # Adjust maximum score
                        max_score=14

                        risk_level="Low"
                        risk_color=$GREEN

                        if [[ $risk_score -ge 5 && $risk_score -lt 9 ]]; then
                            risk_level="Medium"
                            risk_color=$YELLOW
                            medium_risk_extensions+=("$extension_name ($extension_id): Score $risk_score/$max_score")
                        elif [[ $risk_score -ge 9 ]]; then
                            risk_level="High"
                            risk_color=$RED
                            high_risk_extensions+=("$extension_name ($extension_id): Score $risk_score/$max_score")
                        fi

                        echo -e "  ${BLUE}${BOLD}⬢ Risk Assessment:${NC} ${risk_color}${BOLD}$risk_level ($risk_score/$max_score)${NC}"
                        echo -e "${PURPLE}──────────────────────────────────────────────────────────────────${NC}"
                    fi
                fi
            fi
        done

        if [[ $found -eq 0 ]]; then
            echo -e "  ${GREEN}✓ No extensions with suspicious behavior found.${NC}"
            echo -e "${PURPLE}──────────────────────────────────────────────────────────────────${NC}"
        fi
    fi
done

# Display summary of extensions that need investigation
echo ""
echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}${BOLD}║                     SCAN SUMMARY REPORT                      ║${NC}"
echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Display high risk extensions first
if [[ ${#high_risk_extensions[@]} -gt 0 ]]; then
    echo -e "${RED}${BOLD}🔴 HIGH RISK EXTENSIONS - INVESTIGATE IMMEDIATELY:${NC}"
    for ext in "${high_risk_extensions[@]}"; do
        echo -e "   ${RED}⚠ $ext${NC}"
    done
    echo ""
fi

# Display medium risk extensions
if [[ ${#medium_risk_extensions[@]} -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}🟡 MEDIUM RISK EXTENSIONS - INVESTIGATE:${NC}"
    for ext in "${medium_risk_extensions[@]}"; do
        echo -e "   ${YELLOW}⚠ $ext${NC}"
    done
    echo ""
fi
