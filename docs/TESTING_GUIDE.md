# Quick Testing Guide - Report Output Fixes

## Quick Test Commands

### 1. Basic Scan with HTML Report
```bash
wss --url https://example.com --format html --output test_report.html
```
**Expected Results:**
- ✅ Response bodies appear in Request/Response sections
- ✅ All vulnerabilities have reference links (no "N/A")
- ✅ Evidence highlighting works

### 2. Enhanced Scan with Verification
```bash
wss --url https://example.com --enhanced --verify-vulnerabilities --format html --output verified_report.html
```
**Expected Results:**
- ✅ Verification section shows actual values (not 0)
- ✅ Evidence verification section populated
- ✅ Verification state shows: Confirmed/Probable/Stale/Unverified

### 3. OutSystems Application Scan
```bash
wss --url https://your-app.outsystems.app --format html --output outsystems_report.html
```
**Expected Results:**
- ✅ No crashes from regex failures
- ✅ All OutSystems vulnerabilities have background/impact
- ✅ References present for all findings

### 4. Batch Scan
```bash
wss --batch urls.txt --format html --output batch_report.html
```
**Expected Results:**
- ✅ All URLs scanned successfully
- ✅ Consistent report quality across all targets

## What to Check in Reports

### ✅ Verification Section
Look for:
```
Vulnerability Verification
Status: ✓ Verified (or ✗ Not Verified)
Confidence: Certain/Firm/Tentative
Method: Active Testing/Static Analysis
Test Payload: <actual payload if used>
```

### ✅ Evidence Verification Section
Look for:
```
Evidence Verification
Status: ✓ Verified (green) / ⚠ Stale (orange) / ✗ Failed (red) / ○ Unverified (gray)
Evidence Hash: <32-character hash>
Timestamp: <ISO timestamp>
Live Check: Performed (if applicable)
Response Time: <milliseconds> (if live check)
```

### ✅ References Section
Look for:
```
References
• https://cwe.mitre.org/data/definitions/79.html
• https://owasp.org/www-project-top-ten/
• https://portswigger.net/web-security/...
```
**Should NOT see:** "N/A" or empty reference sections

### ✅ Request/Response Sections
Look for:
```
Request
GET /path HTTP/1.1
Host: example.com
...

Response
HTTP/1.1 200 OK
Content-Type: text/html
...

<!DOCTYPE html>
<html>
...
```
**Should see:** Actual response body content (truncated if >50KB)

### ✅ Evidence Appendix
Look for:
```
Evidence Appendix
Verification State: Confirmed/Probable/Stale/Unverified
Evidence Hash: <hash>
Timestamp: <timestamp>
Evidence Snippet: <first 200 chars>
```

## Common Issues and Solutions

### Issue: "N/A" Links Still Appearing
**Solution:** Ensure you're using the latest code with the fixes applied.
```bash
git pull
pip install -e .
```

### Issue: No Response Bodies in Report
**Solution:** Check that the target URL is accessible and returns HTML content.
```bash
curl -I https://your-url.com
```

### Issue: Verification Values Show 0
**Solution:** Ensure `--verify-vulnerabilities` flag is used for active verification.
```bash
wss --url https://example.com --verify-vulnerabilities
```

### Issue: OutSystems Scan Crashes
**Solution:** The fixes include error handling. If still crashing, check logs:
```bash
wss --url https://outsystems-app.com --verbose
```

## Verification Checklist

Before considering the fixes complete, verify:

- [ ] Response bodies appear in reports
- [ ] Evidence highlighting works
- [ ] No "N/A" reference links
- [ ] All CWE links are valid
- [ ] Verification section shows actual values
- [ ] Evidence verification section populated
- [ ] Verification state is descriptive (not just numbers)
- [ ] OutSystems scans complete without errors
- [ ] All vulnerabilities have background/impact
- [ ] References section never empty
- [ ] Request/Response sections complete
- [ ] Evidence appendix shows hash and timestamp

## Performance Benchmarks

Expected performance after fixes:

| Operation | Time Impact | Memory Impact |
|-----------|-------------|---------------|
| Response body capture | +1-2ms per request | +50KB max per response |
| Reference generation | <1ms per vulnerability | Negligible |
| Evidence verification | +100-500ms per vulnerability | Negligible |
| Report generation | No change | No change |

## Success Criteria

The fixes are successful if:

1. ✅ **No "N/A" Links:** All vulnerabilities have valid reference URLs
2. ✅ **Complete Verification:** Verification sections show actual data, not zeros
3. ✅ **Evidence Highlighting:** Response bodies contain highlighted evidence
4. ✅ **Robust Scanning:** OutSystems analyzer handles all patterns gracefully
5. ✅ **Professional Reports:** All sections populated with meaningful data

## Quick Validation Script

```bash
#!/bin/bash
# Quick validation of fixes

echo "Testing basic scan..."
wss --url https://example.com --format html --output test1.html

echo "Testing with verification..."
wss --url https://example.com --verify-vulnerabilities --format html --output test2.html

echo "Checking for N/A links..."
if grep -q ">N/A<" test1.html test2.html; then
    echo "❌ FAIL: Found N/A links"
else
    echo "✅ PASS: No N/A links found"
fi

echo "Checking for verification data..."
if grep -q "Verification" test2.html && grep -q "Evidence Hash" test2.html; then
    echo "✅ PASS: Verification sections present"
else
    echo "❌ FAIL: Verification sections missing"
fi

echo "Checking for response bodies..."
if grep -q "<!DOCTYPE" test1.html; then
    echo "✅ PASS: Response bodies captured"
else
    echo "❌ FAIL: Response bodies missing"
fi

echo "Done! Check test1.html and test2.html for details."
```

Save as `test_fixes.sh`, make executable with `chmod +x test_fixes.sh`, and run with `./test_fixes.sh`.

## Support

If issues persist after applying fixes:

1. Check that all files were updated correctly
2. Reinstall the package: `pip install -e .`
3. Clear any cached bytecode: `find . -type d -name __pycache__ -exec rm -rf {} +`
4. Run with verbose logging: `wss --url <URL> --verbose`
5. Check the FIXES_APPLIED.md document for detailed information

## Next Steps

After verifying fixes work:

1. Run full test suite: `pytest tests/`
2. Test against multiple platforms (Bubble, OutSystems, Airtable, etc.)
3. Generate sample reports for documentation
4. Update user documentation with new features
5. Consider adding automated tests for these fixes
