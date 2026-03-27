# VulnAI: Full Capability Demonstration Guide

## **Email Security (Core Feature)**

### Right-Click Email Tests
```
1. "Right-click email" → Sender Validation
   "Is this email from Amazon really from Amazon? Checks SPF/DMARC"

2. "Right-click email link" → Malicious Link Detection
   "Does this email contain phishing links? Checks URLhaus + heuristics"

3. "Right-click email" with malicious content
   "This email claims to be from PayPal but has a link to paypal-verify.tk"
   → Shows: Sender safe ✅ | Link dangerous 🚨
```

### Chat with Email Content
```
POST /chat/check-email-links
- "Check this email for malicious links: [paste email content]"
- "Analyze this suspicious email I received about account verification"
- "Is this payment update email legitimate? [include subject + body]"
```

---

## **Website Security**

### Test Website Analysis
```
1. Legitimate site: "Is google.com safe to visit?"
   → Shows SSL certs ✅, security headers ✅, reputation ✅

2. Suspicious domain: "Is secure-verify-amazon-account.tk safe?"
   → Shows domain reputation issues, suspicious characteristics

3. Shortened URL: "Is bit.ly/something safe to click?"
   → Can't verify destination, recommends caution
```

---

## **CVE & Vulnerability Intelligence**

### Direct CVE Search
```
1. By CVE ID: "CVE-2024-1234"
   → Shows vulnerability details, plain language explanation

2. By product: "OpenSSL vulnerabilities"
   → Lists all known CVEs for that product

3. By urgency: "What critical vulnerabilities were reported this week?"
   → Threat intelligence feed translated to plain language
```

---

## **Real-World Security Questions (General Chat)**

### Phishing Identification
```
1. "Is this email phishing?"
   → Ask about sender, links, tone, requests for data

2. "How do I spot a phishing email?"
   → Red flags, examples, protection tips

3. "This email asks me to verify my account - should I click?"
   → Analysis without needing full email content
```

### Link Safety
```
1. "Is it safe to click a link from unknown sender?"
   → Risk assessment, best practices

2. "What do I do if I already clicked a malicious link?"
   → Step-by-step incident response

3. "How can I tell a legitimate from fake link?"
   → Domain analysis techniques
```

### Attachment Safety
```
1. "Is it safe to open a PDF from unknown sender?"
   → Risk factors, when to be cautious

2. "What file types are dangerous?"
   → Safe vs risky extensions, why

3. "I opened a suspicious attachment, what now?"
   → Immediate actions to take
```

### Account Security
```
1. "How do I protect my passwords?"
   → Best practices, password manager benefits

2. "Should I use the same password everywhere?"
   → Why not, password hygiene

3. "Has my email been in a breach?"
   → Breach checking, what to do if compromised

4. "Someone has my password, what do I do?"
   → Password reset, account recovery steps
```

### Practical Scenarios
```
1. "My bank never emails me for transactions - why did I get this?"
   → Phishing detection, legitimate bank behavior

2. "The email looks like it's from my boss but feels weird"
   → Business email compromise (BEC) detection

3. "I got a package delivery notification I wasn't expecting"
   → Phishing delivery scam patterns
```

---

## **Breach & Compromise Checking**

### Email Compromise History
```
1. "Has my email been compromised?"
   → Breach database check, results

2. "Is colki@example.com in a data breach?"
   → Historical breach lookup

3. "What was exposed in the [breach name] incident?"
   → Breach details, what to do
```

---

## **Multi-Turn Conversation (Sessions)**

### Extended Security Analysis
```
User: "I got a suspicious email"
AI: [Analyzes email, flags risks]

User: "I think I clicked the link - what do I do?"
AI: [Remembers context, provides incident response]

User: "Should I change my password?"
AI: [Gives step-by-step password reset + monitoring]

User: "How do I prevent this in the future?"
AI: [Proactive recommendations based on how they got compromised]
```

---

## **Threat Intelligence Feed**

### Daily Security Briefing
```
GET /chat/threat-intelligence
→ Shows:
  - Critical vulnerabilities for today
  - Plain language summaries
  - Affected products/versions
  - What non-technical users need to do
  - Urgent alerts vs this-week threats
```

---

## **Demo Scenarios (Proof of Concept)**

### Scenario 1: Phishing Email Caught
```
Extension user right-clicks email from "support@paypal-verify.tk"
Email body: "Click here to verify your account"

Result:
- Sender: Contains typosquatted domain (paypal-verify)
- Link: paypal-verify.tk flagged as phishing pattern
- Overall: 🚨 DO NOT CLICK
- Action: Report to your email provider

→ Proves: Detects what Google Safe Browsing might miss
```

### Scenario 2: Compromised Legitimate Account
```
Email from: boss@company.com (SPF/DMARC ✅)
Content: "Click here for urgent financial approval"
Link: https://fake-company-finances.tk

Result:
- Sender: Legitimate ✅ (real company, has proper auth)
- Content: Account likely compromised 🚨 (unusual request pattern)
- Link: Malicious 🚨 (fake financial domain)
- Overall: Your boss's account was hacked, don't click

→ Proves: Context-aware detection (doesn't blame sender, flags threat)
```

### Scenario 3: Zero-Day Phishing Pattern
```
Email from: internal@company.com
Link: https://companyname-secure-verify.com (hasn't been seen before)

Result (without URLhaus):
- Heuristic detection: Suspicious subdomain pattern
- Domain analysis: Excessive hyphens + unusual structure
- Confidence: Medium (pattern match, not database)
- Action: Be cautious, verify with sender directly

→ Proves: Fallback detection works without API databases
```

### Scenario 4: Safe Email, Suspicious Link
```
Email from: mom@gmail.com (✅ legitimate personal email)
Link: bit.ly/xyz (shortened URL, can't verify destination)

Result:
- Sender: Personal email, legitimate ✅
- Link: Shortened URL - can't verify destination ⚠️
- Overall: Sender is trusted, but be cautious of link
- Action: Ask sender "Did you send this?" before clicking

→ Proves: Smart verdicts prevent false positives
```

---

## **Live Testing Commands**

### Test Email Endpoint
```bash
curl -X POST https://vuln-ai.onrender.com/chat/check-email-links \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Urgent: Verify Your Account",
    "content": "<p>Click <a href=\"https://amazon-verify-account.tk\">here</a> to verify</p>",
    "recipients": ["user@gmail.com"]
  }'
```

### Test Website Endpoint
```bash
curl -X POST https://vuln-ai.onrender.com/chat/analyze-website \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.tk"}'
```

### Test General Chat
```bash
curl -X POST https://vuln-ai.onrender.com/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "CVE-2024-1234",
    "sessionId": "new"
  }'
```

---

## **What Makes VulnAI Different (Highlight in Demos)**

Use these talking points during demonstrations:

1. **"Gmail missed this but VulnAI didn't"**
   - Show phishing email with typosquatted domain
   - Highlight heuristic detection (not database dependent)

2. **"Our AI explains WHY it's dangerous"**
   - Don't just say "unsafe"
   - Explain: "This domain imitates Amazon by using amazon-verify-account.tk - that's a typosquatting attack"

3. **"Context matters - we don't false positive"**
   - Legitimate sender + malicious link = Flag content, not sender
   - Prevents alert fatigue

4. **"Works even when APIs fail"**
   - Show heuristic detection catching patterns
   - No dependency on external threat databases

5. **"One tool replaces many"**
   - Sender validation + link checking + breach history in one click
   - No tool switching needed

---

## **Order for Optimal Demo**

```
1. Start with email security (most relatable)
   Right-click email → Show sender validation
   Right-click link → Show malicious link detection

2. Show context-aware intelligence
   Email with malicious link but trusted sender
   → Demonstrate why this is smarter than blanket blocking

3. Show fallback heuristics
   New/unknown phishing domain
   → Demonstrate detection without database lookup

4. Show general capabilities
   Ask about CVE → Breach check → Real-world scenarios
   → Demonstrate VulnAI is full security assistant

5. Close with threat intelligence
   Check threat feed → Show plain language translations
   → Demonstrate non-technical accessibility
```

---

This covers **every capability** of VulnAI. Pick 3-4 scenarios based on your audience and walk through them to show what makes VulnAI uniquely valuable.
