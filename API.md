# VulnAI Security Assistant API Documentation

## Overview

VulnAI is an AI-powered security vulnerability chatbot that helps users with both technical security questions and real-world security scenarios. It provides intelligent, non-technical responses to everyday security concerns while offering detailed CVE analysis for technical queries.

**Base URL:** `http://localhost:3000`

**API Version:** 1.0.0

---

## Table of Contents

- [Authentication](#authentication)
- [Session Management](#session-management)
- [Endpoints](#endpoints)
  - [POST /chat](#post-chat)
  - [GET /chat/help](#get-chathelp)
- [Request/Response Models](#requestresponse-models)
- [Usage Examples](#usage-examples)
- [Real-World Scenarios](#real-world-scenarios)
- [CVE Search](#cve-search)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

---

## Authentication

Currently, no authentication is required. All endpoints are publicly accessible.

---

## Session Management

### What is a Session?

A session maintains conversation context across multiple requests. This allows the chatbot to remember previous messages and provide better follow-up responses.

### Session Features

- **Automatic Generation**: If you don't provide a `sessionId`, one is automatically generated
- **Persistence**: Sessions last for **30 minutes** of inactivity
- **Context Memory**: The chatbot remembers the entire conversation history within a session
- **UUID Format**: `session-550e8400-e29b-41d4-a716-446655440000`

### How to Use Sessions

#### First Request (New Session)
```http
POST /chat HTTP/1.1
Content-Type: application/json

{
  "message": "Should I trust this email?"
}
```

**Response includes `sessionId`:**
```json
{
  "response": "⚠️ Security Concern Detected...",
  "sessionId": "session-abc123def456"
}
```

#### Follow-up Request (Same Session)
```http
POST /chat HTTP/1.1
Content-Type: application/json

{
  "message": "The sending address is admin@bank-security.com",
  "sessionId": "session-abc123def456",
  "context": "It's asking me to verify my account"
}
```

The chatbot now has context from both messages and can provide better responses.

---

## Endpoints

### POST /chat

Send a message to the security assistant and receive analysis or recommendations.

#### Request

```
POST /chat
Content-Type: application/json
```

#### Request Body

```typescript
{
  "message": string;              // Required: Your security question
  "context?"?: string;            // Optional: Additional context (e.g., sender's email, URL, etc.)
  "sessionId?"?: string;          // Optional: Session ID to continue conversation
  "vulnerabilityType?"?: string;  // Optional: Hint about vulnerability type
}
```

#### Response

```typescript
{
  "response": string;    // The assistant's response
  "sessionId": string;   // Session ID for continuing conversation
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid request (missing message) |
| 500 | Internal server error |

#### Example Requests

##### Basic Security Question
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Is this email safe?"}'
```

##### With Context
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Is this email safe?",
    "context": "It claims to be from my bank but the sender looks suspicious"
  }'
```

##### Continuing Conversation
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "The sender says admin@bankname.com",
    "sessionId": "session-abc123def456",
    "context": "but the domain is not their official domain"
  }'
```

---

### GET /chat/help

Get a comprehensive guide of available commands and features.

#### Request

```
GET /chat/help
```

#### Response

```typescript
{
  "response": string;    // Formatted help message
  "sessionId": string;   // Empty for help endpoint
}
```

#### Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |

#### Example

```bash
curl http://localhost:3000/chat/help
```

---

## Request/Response Models

### ChatRequestDto

```typescript
interface ChatRequestDto {
  /**
   * Your security question or CVE ID
   * Examples: "Should I trust this email?", "CVE-2024-1234", "OpenSSL vulnerabilities"
   */
  message: string;

  /**
   * Additional context for your question
   * Will be remembered in the conversation
   * Examples: "sender@company.com", "https://example.com", "asks for password"
   */
  context?: string;

  /**
   * Session ID to maintain conversation history
   * If not provided, a new session is created
   * Format: "session-UUID"
   */
  sessionId?: string;

  /**
   * Type of vulnerability you're asking about
   * Helps the system understand your intent better
   */
  vulnerabilityType?: 
    | 'phishing'
    | 'email_trust'
    | 'link_safety'
    | 'attachment_safety'
    | 'website_trust'
    | 'social_engineering'
    | 'password_breach'
    | 'account_security'
    | 'general';
}
```

### ChatResponseDto

```typescript
interface ChatResponseDto {
  /**
   * The assistant's response
   * For real-world scenarios: plain-language advice
   * For CVE queries: technical details
   */
  response: string;

  /**
   * Session ID for continuing the conversation
   * Save this to maintain context across requests
   */
  sessionId: string;
}
```

---

## Usage Examples

### Example 1: New User Getting Help

**Request:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "hi"}'
```

**Response:**
```json
{
  "sessionId": "session-550e8400-e29b-41d4-a716-446655440000",
  "response": "👋 Welcome to VulnAI Security Assistant!\n\nI'm here to help you with security questions. I can assist with:\n\n**For everyday security concerns** (simple language):\n- \"Should I trust this email?\"\n- \"Is this link safe to click?\"\n..."
}
```

---

### Example 2: Email Safety Check (Follow-up)

**Request 1 - Initial Question:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Is this email safe? It claims to be from my bank"
  }'
```

**Response 1:**
```json
{
  "sessionId": "session-550e8400-e29b-41d4-a716-446655440000",
  "response": "⚠️ Security Concern Detected: Determining if an email from a company is legitimate\n\n**Watch out for:**\n• The sender's email might be spoofed\n• Check if this matches official domains\n...\n\n**Action Steps:**\n1. Check the sender's email address carefully\n2. Look for official branding\n3. Contact the bank directly before clicking links"
}
```

**Request 2 - Follow-up with more info:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "the sender address is admin@banksecurity2024.com",
    "sessionId": "session-550e8400-e29b-41d4-a716-446655440000",
    "context": "It says my account has suspicious activity and I need to verify"
  }'
```

**Response 2:**
```json
{
  "sessionId": "session-550e8400-e29b-41d4-a716-446655440000",
  "response": "🚨 **This looks VERY suspicious!**\n\nHere's why:\n\n❌ **Red flags:**\n- The domain is NOT the official bank domain\n- Banks never ask you to verify in emails\n- The urgency is a common phishing tactic\n\n✅ **What you should do right now:**\n1. **Do NOT click any links in the email**\n2. **Do NOT reply with personal information**\n3. Delete the email\n4. Go to your bank's official website (type it yourself)\n5. Log in and check if there's a real alert\n6. Report the email as phishing to your bank\n\n**More info:** Related CVEs: CVE-2023-46805, CVE-2022-41080"
}
```

---

### Example 3: CVE Search

**Request:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "CVE-2024-1234"}'
```

**Response:**
```json
{
  "sessionId": "session-new-uuid",
  "response": "**CVE-2024-1234**\n\n**Severity:** CRITICAL\n**CVSS Score:** 9.8/10\n**Published:** 2024-01-15\n\n**Description:**\nA critical vulnerability in OpenSSL...\n\n**Affected Products:**\n- OpenSSL 3.0.x before 3.0.8\n- OpenSSL 3.1.x before 3.1.0\n\n**Remediation:**\nUpgrade to patched versions immediately...\n\n**Status:** 🔴 ACTIVELY EXPLOITED"
}
```

---

### Example 4: Product Vulnerabilities

**Request:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "OpenSSL vulnerabilities"}'
```

**Response:**
```json
{
  "sessionId": "session-new-uuid",
  "response": "🔍 **Vulnerabilities for OpenSSL**\n\nFound: **45** vulnerabilities\n\nTop Recent CVEs:\n• **CVE-2024-1234** [CRITICAL] - 9.8/10\n• **CVE-2024-5678** [HIGH] - 8.1/10\n...\n\n**📊 Threat Analysis:**\n• Threat Level: **HIGH**\n• Risk Score: 87/100\n• Exploitable CVEs: 12\n\n**🎯 Recommendations:**\n1. Update OpenSSL immediately\n2. Review current OpenSSL version: openssl version\n3. Test application compatibility before deploying\n4. Monitor for exploitation attempts"
}
```

---

## Real-World Scenarios

The chatbot intelligently detects and handles these real-world security concerns:

### 1. Email Safety (email_trust)
Ask if an email is legitimate or trustworthy.

**Examples:**
- "Is this email safe?"
- "Should I trust this sender?"
- "Should I reply to this email?"
- "This email seems suspicious"

**What you get:**
- Warning signs to look for
- Whether to click links/reply
- How to verify with the company
- Related CVEs for email-based attacks

---

### 2. Phishing Detection (phishing)
Get help identifying phishing attempts.

**Examples:**
- "Is this phishing?"
- "This email looks like a scam"
- "Is this a fake email?"
- "Someone is trying to trick me"

**What you get:**
- Common phishing indicators
- Red flags in the message
- What NOT to do
- How to report it
- Self-protection steps

---

### 3. Link Safety (link_safety)
Check if a link is safe to click.

**Examples:**
- "Is this link safe?"
- "Can I click this?"
- "Should I open this URL?"
- "Is this domain legitimate?"

**What you get:**
- Domain analysis
- URL structuring advice
- HTTPS/security indicators
- Whether to click or avoid

---

### 4. Attachment Safety (attachment_safety)
Determine if a file is safe to open.

**Examples:**
- "Is it safe to open this file?"
- "Should I download this attachment?"
- "Is this file dangerous?"
- "PDF from unknown sender - safe?"

**What you get:**
- File type safety assessment
- Risks for different extensions
- Macro warning signs
- Safe ways to check files

---

### 5. Website Trust (website_trust)
Verify if a website is legitimate.

**Examples:**
- "Is this website safe to buy from?"
- "Should I trust this site?"
- "Is this a fake website?"
- "Can I enter my credit card here?"

**What you get:**
- Domain legitimacy check
- HTTPS/security indicators
- Whether to proceed
- How to verify authenticity

---

### 6. Social Engineering (social_engineering)
Recognize manipulation attempts.

**Examples:**
- "Someone is asking weird questions"
- "Is this a social engineering attempt?"
- "I got a suspicious call"
- "Does this seem like a scam?"

**What you get:**
- Recognizing social engineering
- Common manipulation tactics
- What NOT to share
- Who to report to

---

### 7. Password Breach (password_breach)
Get help if your password was compromised.

**Examples:**
- "My password was leaked"
- "I think I was hacked"
- "My account was compromised"
- "Should I change my password?"

**What you get:**
- Immediate action steps
- Which accounts to check
- How to create strong passwords
- Password manager recommendations

---

### 8. Account Security (account_security)
General account protection advice.

**Examples:**
- "How do I secure my account?"
- "Should I enable 2FA?"
- "How do I protect myself?"
- "What are best practices?"

**What you get:**
- Step-by-step security setup
- Multi-factor authentication guide
- Password manager recommendations
- Regular security practices

---

## CVE Search

### Searching for CVEs

**By CVE ID:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "CVE-2024-1234"}'
```

**By Product Name:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Apache vulnerabilities"}'
```

**By Severity:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "critical vulnerabilities"}'
```

**Recent Vulnerabilities:**
```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "recent CVEs"}'
```

---

## Error Handling

### Common Errors

#### 400 Bad Request
```json
{
  "statusCode": 400,
  "message": "message property is required"
}
```

**Cause:** Missing `message` field in request body.

**Solution:** Always include a `message` field.

---

#### 500 Internal Server Error
```json
{
  "statusCode": 500,
  "message": "Internal server error"
}
```

**Cause:** Server-side issue (network error, API timeout, etc.).

**Solution:** Retry the request. Check server logs if issue persists.

---

### Error Response Format

All error responses follow this format:
```typescript
{
  "statusCode": number;
  "message": string;
  "error": string;
}
```

---

## Rate Limiting

Currently, there are no rate limits on the API. However, consider implementing them in production:

**Recommended:**
- 100 requests per minute per IP
- 1000 requests per day per IP

---

## Frontend Integration Example

### React Example

```typescript
import React, { useState } from 'react';
import axios from 'axios';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export function ChatApp() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [context, setContext] = useState('');
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const sendMessage = async () => {
    if (!input.trim()) return;

    setLoading(true);
    try {
      const response = await axios.post('http://localhost:3000/chat', {
        message: input,
        context: context || undefined,
        sessionId: sessionId || undefined,
      });

      // Save session ID for future requests
      if (response.data.sessionId && !sessionId) {
        setSessionId(response.data.sessionId);
      }

      // Add messages to chat
      setMessages([
        ...messages,
        { id: Date.now().toString(), role: 'user', content: input, timestamp: new Date() },
        { id: (Date.now() + 1).toString(), role: 'assistant', content: response.data.response, timestamp: new Date() },
      ]);

      setInput('');
      setContext('');
    } catch (error) {
      console.error('Failed to send message:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chat-container">
      <div className="messages">
        {messages.map((msg) => (
          <div key={msg.id} className={`message ${msg.role}`}>
            <p>{msg.content}</p>
          </div>
        ))}
      </div>

      <div className="input-area">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
          placeholder="Ask a security question..."
        />
        <input
          type="text"
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Additional context (optional)"
        />
        <button onClick={sendMessage} disabled={loading}>
          {loading ? 'Sending...' : 'Send'}
        </button>
      </div>

      {sessionId && <p>Session: {sessionId}</p>}
    </div>
  );
}
```

---

## Best Practices

### 1. Always Save Session ID
```javascript
const sessionId = response.data.sessionId;
localStorage.setItem('vuln-session', sessionId);
```

### 2. Preserve Conversation Context
Store messages in your frontend so users can see the full conversation.

### 3. Handle Long Responses
Responses can be quite long. Ensure your UI can handle multiline text with markdown formatting.

### 4. Provide Context When Possible
```javascript
{
  "message": "Is this email safe?",
  "context": "From: admin@bankname.com, Content: Asking to verify account"
}
```

### 5. Show Typing Indicator
Use `loading` state to show the user that a response is being generated.

---

## Support

For issues or questions about the API:
1. Check the [Error Handling](#error-handling) section
2. Review the [Usage Examples](#usage-examples)
3. Check server logs for detailed error messages

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-26 | Initial release with session management and real-world scenarios |

---

## License

VulnAI is licensed under UNLICENSED.
