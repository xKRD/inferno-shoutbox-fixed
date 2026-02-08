# Inferno Shoutbox Security Patches

Critical security vulnerability fixes for the Inferno Shoutbox plugin (MyBB)

**Discovered by:** [Shada Kurdistani](https://hackers.krd/KHF-Shada-Kurdistani) & [Zed](https://hackers.krd/KHF-Zed)  
**Forum:** [Kurdistan Hackers Forums](https://www.hackers.krd)  
**Date:** February 2026

[![Security](https://img.shields.io/badge/Security-Critical-red.svg)](https://github.com/yourusername/inferno-shoutbox-patches)
[![MyBB](https://img.shields.io/badge/MyBB-1.8.x-blue.svg)](https://mybb.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ⚠️ CRITICAL SECURITY ALERT

Two critical zero-day vulnerabilities have been discovered in the Inferno Shoutbox plugin for MyBB. **Immediate patching is strongly recommended.**

---

## 🔒 Vulnerabilities Discovered

### 1. Cross-Site Request Forgery (CSRF)
**Severity:** 🟡 Medium  
**CVSS Score:** 5.4  
**Discovered by:** [Zed](https://hackers.krd/KHF-Zed)  
**CVE:** Pending

#### Description
The shoutbox `newshout` and  `deleteshout`, `updateshout` and all others actions completely lacks CSRF token validation, allowing attackers to forge requests that post messages on behalf of authenticated users without their knowledge or consent.

#### Proof of Concept
```http
GET /infernoshout.php?action=newshout&shout=slaw&styles%5Bbold%5D=false&styles%5Bitalic%5D=false&styles%5Bunderline%5D=false&styles%5Bcolor%5D=Red&styles%5Bfont%5D= HTTP/2
Host: victim-site.com
```

**Attack Vector:**
```html
<!-- Attacker hosts this on their site -->
<img src="https://victim-site.com/infernoshout.php?action=newshout&shout=HACKED&styles%5Bcolor%5D=Red" style="display:none">
```

When an authenticated user visits the attacker's page, a message is automatically posted to the shoutbox without their permission.

#### Impact
- ✗ Unauthorized message posting - Spam injection into shoutbox
- ✗ Social engineering attacks - Messages appear from legitimate users
- ✗ Reputation damage - Offensive content posted under user accounts
- ✗ Phishing campaigns - Malicious links distributed via trusted accounts
- ✗ Session riding - Actions performed without user awareness

#### Technical Details
- **Missing:** CSRF token validation in POST/GET requests
- **Vulnerable Endpoint:** `/infernoshout.php?action=newshout`
- **Authentication Required:** Yes (victim must be logged in)
- **Exploitation Complexity:** Low - Simple URL manipulation

---

### 2. Insecure Direct Object Reference (IDOR)
**Severity:** 🔴 HIGH  
**CVSS Score:** 7.5  
**Discovered by:** [Shada Kurdistani](https://github.com/xKRD/)  
**CVE:** Pending

#### Description
The `removeshout` action contains a **critical authorization flaw** that allows **completely unauthenticated users (guests)** to delete ANY shoutbox message by simply manipulating the `sid` (shout ID) parameter. No user validation, permission checks, or authentication is required whatsoever.

#### Proof of Concept
```http
GET /infernoshout.php?action=removeshout&sid=701 HTTP/2
Host: hackers.krd
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: */*
Accept-Language: en-US,en;q=0.9
X-Requested-With: XMLHttpRequest
```

**Exploitation Steps:**
1. Identify target shoutbox (no account needed)
2. Enumerate shout IDs by incrementing the `sid` parameter
3. Send DELETE requests for each ID
4. **Result:** Complete shoutbox wipeout in seconds

**Automated Attack Example:**
```bash
# Delete all shouts from ID 1 to 1000
for i in {1..1000}; do
  curl "https://victim-site.com/infernoshout.php?action=removeshout&sid=$i"
done
```

#### Impact
- ✗ **Mass data destruction** - Entire shoutbox history can be wiped in seconds
- ✗ **Zero authentication required** - Any internet user can exploit this
- ✗ **No authorization checks** - Complete bypass of all access controls
- ✗ **Automated exploitation** - Trivial to script mass deletion attacks
- ✗ **Untraceable vandalism** - No reliable audit trail
- ✗ **Community disruption** - Critical communication channel disabled
- ✗ **Permanent data loss** - User conversations deleted irreversibly

#### Technical Details
- **Missing:** Authentication verification
- **Missing:** Authorization checks (ownership validation)
- **Missing:** CSRF protection on deletion
- **Vulnerable Endpoint:** `/infernoshout.php?action=removeshout`
- **Authentication Required:** **NONE** ⚠️
- **Exploitation Complexity:** Trivial - Single HTTP GET request

---

## 🛡️ Security Patches Included

This repository contains comprehensive security fixes addressing both vulnerabilities:

### CSRF Protection (newshout action)
- ✅ Added CSRF token validation using MyBB's built-in `verify_post_check()` function
- ✅ Implemented proper token generation and verification
- ✅ Added error handling for invalid/missing tokens
- ✅ Maintains backward compatibility with existing functionality

### IDOR Protection (removeshout action)
- ✅ Added mandatory authentication check - guests are blocked
- ✅ Implemented ownership verification - users can only delete their own shouts
- ✅ Added administrator override - admins/moderators can delete any shout
- ✅ Proper error responses for unauthorized attempts
- ✅ Activity logging for audit trail

### Additional Security Improvements
- ✅ Input validation and sanitization
- ✅ Rate limiting recommendations
- ✅ Security headers implementation
- ✅ Comprehensive error handling

---

## 📋 Affected Versions

- **Inferno Shoutbox:** All versions prior to patch
- **MyBB:** Tested on 1.8.x series
- **PHP:** 5.6+ to 8.x

**Note:** If you're using a different version, please test thoroughly in a staging environment first.

---

## ⚠️ Disclosure Timeline

- **February 1, 2026** - Vulnerabilities discovered
- **February 2, 2026** - Initial vendor notification attempt
- **February 5, 2026** - Public disclosure with patches
- **[Pending]** - Official vendor patch release

---

## 👏 Credits

**Security Researchers:**
- **[Shada Kurdistani](https://github.com/xKRD/)** - IDOR Vulnerability Discovery & Analysis
- **[Zed](https://hackers.krd/KHF-Zed)** - CSRF Vulnerability Discovery & Analysis

**Organization:**  
**[Kurdistan Hackers Forums](https://www.hackers.krd)** - Community-driven security research

---
---

## 🔗 References

### Security Standards
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP IDOR Prevention Guide](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

### MyBB Documentation
- [MyBB Security Documentation](https://docs.mybb.com/1.8/development/security/)
- [MyBB Plugin Development](https://docs.mybb.com/1.8/development/plugins/)
- [MyBB Security Best Practices](https://docs.mybb.com/1.8/administration/security/)

### Tools & Testing
- [Burp Suite](https://portswigger.net/burp) - Web vulnerability scanner
- [OWASP ZAP](https://www.zaproxy.org/) - Security testing tool
- [curl](https://curl.se/) - Command-line HTTP client
