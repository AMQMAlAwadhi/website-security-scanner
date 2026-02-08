# Security Scanner for Low-Code Platforms: Technical Documentation

## Abstract & Overview
This project provides a specialized security-scanning toolkit for low-code and no-code platforms (Bubble.io, OutSystems, Airtable, Shopify, etc.). It addresses the unique security challenges of these platforms by identifying common misconfigurations, exposed APIs, and platform-specific vulnerabilities.

## Technical Architecture

### Scanner Workflow
1.  **Detection**: The `AdvancedPlatformDetector` identifies the target platform based on HTTP headers, HTML structure, and JS patterns.
2.  **Analysis**: Platform-specific analyzers (e.g., `BubbleAnalyzer`) perform deep inspection of the target's configuration and assets.
3.  **Verification**: The `EvidenceVerifier` re-checks identified vulnerabilities against the live target to reduce false positives.
4.  **Reporting**: Results are normalized by the `ResultStandardizer` and exported via CLI, Web UI, or professional HTML reports.

### Module Structure
-   `src/website_security_scanner/main.py`: Main scanner driver.
-   `src/website_security_scanner/analyzers/`: Platform-specific analysis logic.
-   `src/website_security_scanner/result_standardizer.py`: Centralized scoring and normalization.
-   `src/website_security_scanner/report_generator.py`: HTML report generation.
-   `src/website_security_scanner/web/`: Flask-based web interface.

## Core Components

### Platform Detection System
Uses a weighted heuristic approach to identify platforms. It checks for:
-   Domain patterns (e.g., `bubbleapps.io`)
-   Specific HTML tags and meta-data
-   JavaScript library fingerprints
-   Unique HTTP response headers

### Evidence Verification Engine
Performs non-destructive re-checking of vulnerabilities by:
-   Requesting specific assets or API endpoints identified in the analysis.
-   Comparing live responses with expected vulnerable patterns.
-   Updating confidence scores based on verification results.

### Confidence Scoring Algorithm
Computes a confidence level (Certain, Firm, Tentative) based on:
-   Directness of evidence (e.g., a leaked secret vs. a missing header).
-   Verification status (verified findings get higher confidence).
-   Signal strength from multiple detection patterns.

## Scoring & Risk System

### Severity Levels
-   **Critical**: Immediate threat to data integrity or system access.
-   **High**: Significant risk of unauthorized access or data exposure.
-   **Medium**: Moderate risk, often requiring chaining with other issues.
-   **Low**: Minor issues or best-practice violations.
-   **Info**: General information or configuration details.

### Overall Risk Score (0-100)
Calculated using a logarithmic weighted sum of vulnerabilities:
`score = 100 * (1 - e^(-total_weighted_risk / 25.0))`

Where `total_weighted_risk` is the sum of (Severity Weight × Confidence Multiplier) for all findings.

### Risk Level Mapping
-   **80-100**: Critical Risk
-   **60-79**: High Risk
-   **40-59**: Medium Risk
-   **20-39**: Low Risk
-   **1-19**: Minimal Risk
-   **0**: No Risk

## Security Considerations
-   **Safe Scanning**: All checks are non-destructive and avoid making state-changing requests.
-   **Rate Limiting**: Integrated throttling prevents accidental Denial of Service against targets.
-   **Privacy**: No credentials or sensitive user data are stored by the scanner.

## Future Development
-   Machine Learning based vulnerability detection.
-   Expanded support for more low-code platforms (e.g., Retool, AppSheet).
-   Integration with CI/CD pipelines for automated security checks.
