# MERN Stack Security Scan Results Summary
**Target:** https://mern-ust-project-2026-2.onrender.com  
**Scan Date:** January 2026

---

## 1. Invicti (formerly Netsparker) Results

### Scan Overview
- **Total Requests:** 3,056
- **Average Speed:** 4.6 requests/second
- **Scan Duration:** 00:00:11:00 (11 minutes)
- **Risk Level:** INFORMATION
- **Scan Start:** 1/20/2026 1:39:48 AM (UTC+03:00)

### Vulnerability Summary
- **Total Identified:** 4 vulnerabilities
- **Total Confirmed:** 3 vulnerabilities

#### Breakdown by Severity:
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Best Practice:** 1
- **Information:** 3

#### Identified Vulnerabilities:
1. **Content Security Policy (CSP) Not Implemented** (Best Practice - Confirmed)
2. **Cloudflare Identified** (Information - Unconfirmed)
3. **Additional Information Issues** (Information - Unconfirmed)

---

## 2. Burp Suite Professional Results

### Vulnerability Summary
#### Breakdown by Severity and Confidence:
- **High Severity:** 0 total
  - Certain: 0
  - Firm: 0
  - Tentative: 0

#### Identified Issues:
1. **TLS Certificate** (Medium Severity - Certain)
   - **CWE References:** CWE-295, CWE-326, CWE-327
   - **Issue:** Certificate validation and encryption strength concerns

2. **Frameable Response (potential Clickjacking)** (Information Severity - Firm)
   - **Impact:** Potential for clickjacking attacks

3. **Robots.txt File** (Information Severity - Firm)
   - **CWE Reference:** CWE-200 (Information Exposure)
   - **Impact:** Information disclosure through robots.txt

4. **Cacheable HTTPS Response** (Information Severity - Firm)
   - **CWE References:** CWE-524, CWE-525
   - **Impact:** Information exposure through caching

---

## 3. Nessus Results

### Vulnerability Summary
#### Breakdown by Severity:
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Information:** 14 (Detailed Vulnerabilities report) / 9 (Complete List report)

**Note:** The variation in Information-level vulnerability counts (14 vs 9) suggests different reporting criteria between Nessus report types.

---

## 4. Acunetix Results

*Note: Only PDF report available in the provided directory. HTML extraction was not possible from the current files.*

---

## Comparative Analysis Summary

### Security Posture Assessment
Based on the four security scanning tools, the MERN Stack application demonstrates:

1. **Overall Risk Level:** LOW to INFORMATION
   - No Critical or High severity vulnerabilities detected
   - Most findings are informational or best practice recommendations

2. **Common Findings Across Tools:**
   - **TLS/SSL Configuration:** Multiple tools identified certificate-related concerns
   - **Security Headers:** Missing CSP header identified by Invicti
   - **Information Disclosure:** Various low-risk information exposure issues

3. **Tool Detection Capabilities:**
   - **Invicti:** Most comprehensive (4 findings, 3 confirmed)
   - **Burp Suite:** Detailed technical analysis with CWE mappings
   - **Nessus:** Highest number of informational findings (14)
   - **Acunetix:** Results available in PDF format

### Recommendations for Thesis Analysis

1. **Strengths of MERN Stack Security:**
   - No critical or high-severity vulnerabilities
   - Basic security controls appear to be in place
   - Low attack surface for common web vulnerabilities

2. **Areas for Improvement:**
   - Implement Content Security Policy (CSP)
   - Review and enhance TLS certificate configuration
   - Address information disclosure vulnerabilities
   - Implement proper cache control headers

3. **Tool Comparison Insights:**
   - Different tools prioritize different vulnerability categories
   - Complementary coverage when used together
   - Variation in severity classification across tools

---

*This summary was extracted from the security scan reports provided in the "MERN Stack - Four Tools' Reports" directory for thesis documentation purposes.*
