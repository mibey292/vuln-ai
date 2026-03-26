# VulnAI Added APIs Documentation

## Overview

This document describes the four new API endpoints and their corresponding services added to VulnAI for enhanced security analysis and threat intelligence.

---

## 1. Website Security Analysis

### Service: `WebsiteAnalysisService`
**Location:** `src/external-apis/website-analysis.service.ts`

### Endpoint: `POST /chat/analyze-website`

Analyzes a website for security vulnerabilities, SSL/TLS configuration, security headers, and domain legitimacy.

#### Request
```json
{
  "url": "https://example.com"
}
```

#### Response
```json
{
  "url": "https://example.com",
  "isReachable": true,
  "hasSSL": true,
  "sslGrade": "A",
  "securityHeaders": {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY"
  },
  "redirectChain": ["https://example.com"],
  "suspiciousIndicators": [],
  "riskLevel": "safe",
  "recommendations": [
    "Website appears legitimate and secure"
  ]
}
```

#### Key Features
- **SSL/HTTPS Validation** - Checks certificate validity and grade
- **Security Headers Analysis** - Detects CSP, HSTS, X-Frame-Options, etc.
- **Redirect Chain Detection** - Identifies suspicious redirect patterns
- **Domain Suspicion** - Detects:
  - Brand mimicking (e.g., `paypal.com-check.shop`)
  - Suspicious TLDs (`.tk`, `.ml`)
  - Excessive hyphens or domain length
- **Risk Assessment** - Returns risk level: `safe`, `moderate`, `suspicious`, `dangerous`

#### Use Cases
- Validate if a link provided by user is safe
- Check website security before visiting
- Verify domain legitimacy in suspected phishing attempts

---

## 2. Data Breach Checker

### Service: `BreachCheckService`
**Location:** `src/external-apis/breach-check.service.ts`

### Endpoint: `POST /chat/check-breach`

Checks if an email address or username appears in known data breaches using the haveibeenpwned.com API.

#### Request
```json
{
  "email": "user@example.com",
  "username": "johndoe"
}
```

#### Response
```json
{
  "found": true,
  "plainLanguageWarning": "⚠️ WARNING: This email appears in 2 known data breach(es). You should change your password immediately and monitor your accounts for unusual activity.",
  "breaches": [
    {
      "name": "LinkedIn",
      "breachDate": "2012-05-05",
      "addedDate": "2015-02-09",
      "description": "LinkedIn User Data Breach",
      "count": 6000000
    }
  ]
}
```

#### Key Features
- **Multi-Database Support** - Queries haveibeenpwned.com API v3
- **Dual Checking** - Checks both email and username
- **Plain Language Warnings** - User-friendly, non-technical alerts
- **Breach Details** - Returns:
  - Breach name and date
  - Number of compromised records
  - Description of breach
- **24-Hour Caching** - Improves performance for repeated checks

#### Use Cases
- Verify if credentials have been compromised in breaches
- Alert users about password change necessity
- Account security assessment
- Identity theft prevention

---

## 3. Email Sender Validation

### Service: `EmailValidationService`
**Location:** `src/external-apis/email-validation.service.ts`

### Endpoint: `POST /chat/validate-email`

Validates email sender legitimacy using DNS records and domain analysis.

#### Request
```json
{
  "senderEmail": "support@example.com"
}
```

#### Response
```json
{
  "email": "support@example.com",
  "isValid": true,
  "domain": "example.com",
  "hasMXRecords": true,
  "hasSpfRecord": true,
  "hasDmarcRecord": false,
  "suspicionLevel": "safe",
  "reasons": [],
  "suggestions": [
    "Email appears legitimate"
  ]
}
```

#### Key Features
- **DNS Validation** - Checks:
  - MX Records (mail server configuration)
  - SPF Records (email authentication)
  - DMARC Records (email policy)
- **Domain Suspicion Detection** - Identifies:
  - Dangerous domain patterns (`secure-login`, `verify-account`, `alerts-alerts`)
  - Brand mimicking attempts
  - Suspicious TLDs
- **Suspicion Levels**:
  - `safe` - Legitimate sender
  - `suspicious` - Some red flags
  - `dangerous` - High likelihood of fraud
- **Actionable Suggestions** - Recommendations for users

#### Use Cases
- Verify email sender legitimacy in phishing detection
- Detect spoofed/impersonated email addresses
- Check if email domain setup is authentic
- Assess phishing email claims

---

## 4. Threat Intelligence Feed

### Service: `ThreatIntelligenceService`
**Location:** `src/analytics/threat-intelligence.service.ts`

### Endpoint: `GET /chat/threat-intelligence`

Provides a non-technical threat intelligence feed with the latest critical vulnerabilities and security threats.

#### Request
```
GET /chat/threat-intelligence
```

#### Response
```json
{
  "lastUpdated": "2026-03-26T21:44:51.920Z",
  "summaryForNonTechUsers": "## 🛡️ Security Threat Summary\n\n📊 **This Week**: 3 new vulnerabilities disclosed.\n\n**What to do:**\n1. Check if you use any software mentioned in the threats\n2. Update to the latest version immediately if critical\n3. Enable automatic updates",
  "criticalAlerts": [
    {
      "title": "Critical Windows Vulnerability",
      "plainLanguage": "Hackers could completely control your computer. Update Windows immediately.",
      "urgency": "Act Now",
      "impactScore": 10
    }
  ],
  "thisWeekVulnerabilities": [
    {
      "title": "Chrome Security Update",
      "plainLanguage": "Important update available for your web browser.",
      "urgency": "This Week",
      "impactScore": 6
    }
  ],
  "exploitedNow": [
    {
      "title": "Active Exploit",
      "plainLanguage": "Hackers are actively attacking. Update now.",
      "urgency": "Act Now",
      "impactScore": 10
    }
  ]
}
```

#### Key Features
- **Plain Language Translations** - Technical CVE data converted to user-friendly explanations
- **Urgency Scoring System**:
  - `Act Now` - Actively exploited critical vulnerabilities
  - `This Week` - High severity issues
  - `Soon` - Medium severity
  - `Monitor` - Low severity
- **Impact Scoring** - 1-10 scale for user understanding
- **Non-Technical Summary** - Actionable advice for non-developers
- **1-Hour Caching** - Fresh threat data with performance optimization
- **Data Sources** - Aggregates from:
  - CISA (Cybersecurity & Infrastructure Security Agency)
  - NVD (National Vulnerability Database)
  - GitHub Security Advisories

#### Use Cases
- Non-technical users stay informed about security threats
- Dashboard display of current threat landscape
- Decision-making on update priorities
- Business continuity and security planning

---

## Integration Points

### Module Structure
```
ExternalApisModule
├── BreachCheckService
├── EmailValidationService
├── WebsiteAnalysisService
└── CisaApiService
└── NvdApiService
└── GitHubSecurityService

AnalyticsModule
├── ThreatIntelligenceService (uses CisaApiService, NvdApiService)
└── RiskCalculatorService
└── ThreatAnalyzerService

ChatbotModule (imports ExternalApisModule & AnalyticsModule)
├── ChatbotController (exposes all endpoints)
└── ChatbotService
```

### Dependency Injection
All services are registered in their respective modules and automatically injected into `ChatbotController`.

---

## Caching Strategy

| Service | Cache Key | TTL | Purpose |
|---------|-----------|-----|---------|
| BreachCheckService | `breach:{email\|username}` | 24 hours | Reduce API calls to haveibeenpwned |
| ThreatIntelligenceService | `threat-feed` | 1 hour | Fresh threat data with performance |
| WebsiteAnalysisService | Per-request | None | Real-time analysis needed |
| EmailValidationService | Per-request | None | Real-time DNS checks |

---

## Error Handling

All services implement:
- Try-catch blocks with logging
- Graceful fallbacks for API failures
- User-friendly error messages
- No exposure of sensitive error details

---

## Testing

### Manual Test Commands

**Website Analysis:**
```bash
curl -X POST http://localhost:3000/chat/analyze-website \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com"}'
```

**Breach Check:**
```bash
curl -X POST http://localhost:3000/chat/check-breach \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

**Email Validation:**
```bash
curl -X POST http://localhost:3000/chat/validate-email \
  -H "Content-Type: application/json" \
  -d '{"senderEmail":"support@example.com"}'
```

**Threat Intelligence:**
```bash
curl -X GET http://localhost:3000/chat/threat-intelligence
```

---

## Security Considerations

1. **Rate Limiting** - Consider adding rate limits for external API calls
2. **API Keys** - External APIs (haveibeenpwned) require proper User-Agent headers
3. **Data Privacy** - Email addresses checked against breach database; consider user consent
4. **DNS Timeouts** - Email validation may timeout on networks with DNS restrictions
5. **CORS** - All endpoints protected by CORS configuration (localhost:5173, vuln-ai.geniushackers.guru)

---

## Future Enhancements

- [ ] Security audit mode with conversational questionnaire
- [ ] Threat intelligence cron job for periodic updates
- [ ] Browser extension for real-time link analysis
- [ ] Personal vulnerability watch list
- [ ] Integration with Slack/Teams for alerts
- [ ] Historical threat data tracking
- [ ] Custom risk scoring based on user profile

