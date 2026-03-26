# VulnAI Frontend Developer Guide

This guide helps frontend developers integrate with the VulnAI Security Assistant API.

## Quick Start

### 1. Access Swagger Documentation
When the server is running, visit:
```
http://localhost:3000/api
```

You can test all endpoints directly from the Swagger UI.

### 2. Basic API Call

```bash
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Is this email safe?"}'
```

### 3. With Session Management

```bash
# First request
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hi"}' > response.json

# Extract sessionId from response
SESSION_ID=$(jq -r '.sessionId' response.json)

# Follow-up request
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d "{\"message\": \"More context here\", \"sessionId\": \"$SESSION_ID\"}"
```

---

## Integration Examples

### JavaScript/TypeScript (Fetch API)

```typescript
// Simple message
const response = await fetch('http://localhost:3000/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message: 'Is this email safe?' })
});

const data = await response.json();
console.log(data.response);
console.log('Save this sessionId:', data.sessionId);
```

### JavaScript/TypeScript (Axios)

```typescript
import axios from 'axios';

const client = axios.create({
  baseURL: 'http://localhost:3000',
  timeout: 30000, // CVE searches can take time
});

// Send message
const response = await client.post('/chat', {
  message: 'Should I trust this email?',
  context: 'It claims to be from my bank'
});

console.log(response.data.response);
console.log(response.data.sessionId);
```

### React Hook

```typescript
import { useState } from 'react';
import axios from 'axios';

export function useSecurityChat() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sendMessage = async (message: string, context?: string) => {
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post('http://localhost:3000/chat', {
        message,
        context,
        sessionId: sessionId || undefined,
      });

      setSessionId(response.data.sessionId);
      return response.data.response;
    } catch (err) {
      const errorMsg = axios.isAxiosError(err) 
        ? err.response?.data?.message || err.message
        : 'Unknown error';
      setError(errorMsg);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const resetSession = () => setSessionId(null);

  return { sendMessage, sessionId, loading, error, resetSession };
}
```

### React Component

```typescript
import React, { useState } from 'react';
import { useSecurityChat } from './useSecurityChat';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
}

export function ChatWindow() {
  const { sendMessage, sessionId, loading } = useSecurityChat();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [context, setContext] = useState('');

  const handleSend = async () => {
    if (!input.trim()) return;

    // Add user message
    const userMsg: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: input,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');

    try {
      // Get assistant response
      const response = await sendMessage(input, context);

      const assistantMsg: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response,
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (error) {
      // Show error message
      const errorMsg: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
      };
      setMessages((prev) => [...prev, errorMsg]);
    }
  };

  return (
    <div className="chat-window">
      <div className="messages">
        {messages.map((msg) => (
          <div key={msg.id} className={`message message-${msg.type}`}>
            {msg.type === 'user' ? '👤' : '🛡️'} {msg.content}
          </div>
        ))}
        {loading && <div className="message message-assistant">⏳ Thinking...</div>}
      </div>

      <div className="input-area">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          placeholder="Ask a security question..."
          disabled={loading}
        />

        <input
          type="text"
          value={context}
          onChange={(e) => setContext(e.target.value)}
          placeholder="Additional context (optional)"
          disabled={loading}
        />

        <button onClick={handleSend} disabled={loading}>
          {loading ? 'Sending...' : 'Send'}
        </button>
      </div>

      {sessionId && (
        <div className="session-info">
          Active session: {sessionId.substring(0, 20)}...
        </div>
      )}
    </div>
  );
}
```

### Vue.js

```vue
<template>
  <div class="chat-container">
    <div class="messages">
      <div
        v-for="msg in messages"
        :key="msg.id"
        :class="['message', `message-${msg.type}`]"
      >
        <span v-if="msg.type === 'user'">👤</span>
        <span v-else>🛡️</span>
        {{ msg.content }}
      </div>
      <div v-if="loading" class="message message-assistant">⏳ Thinking...</div>
    </div>

    <div class="input-area">
      <textarea
        v-model="input"
        @keydown.enter.ctrl="sendMessage"
        placeholder="Ask a security question..."
        :disabled="loading"
      />

      <input
        v-model="context"
        type="text"
        placeholder="Additional context (optional)"
        :disabled="loading"
      />

      <button @click="sendMessage" :disabled="loading">
        {{ loading ? 'Sending...' : 'Send' }}
      </button>
    </div>

    <div v-if="sessionId" class="session-info">
      Active session: {{ sessionId.substring(0, 20) }}...
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import axios from 'axios';

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
}

const input = ref('');
const context = ref('');
const messages = ref<Message[]>([]);
const sessionId = ref<string | null>(null);
const loading = ref(false);

const sendMessage = async () => {
  if (!input.value.trim()) return;

  const userMsg: Message = {
    id: Date.now().toString(),
    type: 'user',
    content: input.value,
  };

  messages.value.push(userMsg);
  const message = input.value;
  const ctx = context.value;
  input.value = '';

  loading.value = true;

  try {
    const response = await axios.post('http://localhost:3000/chat', {
      message,
      context: ctx || undefined,
      sessionId: sessionId.value || undefined,
    });

    sessionId.value = response.data.sessionId;

    messages.value.push({
      id: (Date.now() + 1).toString(),
      type: 'assistant',
      content: response.data.response,
    });
  } catch (error) {
    messages.value.push({
      id: (Date.now() + 1).toString(),
      type: 'assistant',
      content: 'Sorry, I encountered an error. Please try again.',
    });
  } finally {
    loading.value = false;
  }
};
</script>
```

---

## Common Patterns

### Pattern 1: Session Persistence (LocalStorage)

```typescript
// Save session
const saveSession = (sessionId: string) => {
  localStorage.setItem('vuln-session-id', sessionId);
};

// Restore session
const getSession = () => {
  return localStorage.getItem('vuln-session-id');
};

// Clear session
const clearSession = () => {
  localStorage.removeItem('vuln-session-id');
};

// In your component:
const sessionId = getSession();

// After sending message:
if (response.data.sessionId) {
  saveSession(response.data.sessionId);
}
```

### Pattern 2: Markdown Response Rendering

```typescript
import ReactMarkdown from 'react-markdown';

export function ChatMessage({ content }: { content: string }) {
  return (
    <div className="message-content">
      <ReactMarkdown
        components={{
          h1: ({ node, ...props }) => <h2 {...props} />,
          code: ({ node, inline, ...props }) => (
            inline ? <code className="inline-code" {...props} /> : <pre><code {...props} /></pre>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
```

### Pattern 3: Auto-Type Detection

```typescript
function detectIntentType(message: string): string | undefined {
  const lowerMsg = message.toLowerCase();

  if (lowerMsg.includes('phish')) return 'phishing';
  if (lowerMsg.includes('email') && lowerMsg.includes('safe')) return 'email_trust';
  if (lowerMsg.includes('link') || lowerMsg.includes('url')) return 'link_safety';
  if (lowerMsg.includes('attach') || lowerMsg.includes('file')) return 'attachment_safety';
  if (lowerMsg.includes('website') || lowerMsg.includes('site')) return 'website_trust';
  if (lowerMsg.includes('call') || lowerMsg.includes('social')) return 'social_engineering';
  if (lowerMsg.includes('password') && lowerMsg.includes('breach')) return 'password_breach';
  if (lowerMsg.includes('account')) return 'account_security';

  return undefined;
}

// Usage:
const vulnerabilityType = detectIntentType(userMessage);
const response = await client.post('/chat', {
  message: userMessage,
  vulnerabilityType,
});
```

---

## Styling Tips

### CSS for Chat Messages

```css
.message {
  padding: 12px 16px;
  margin: 8px 0;
  border-radius: 8px;
  max-width: 80%;
}

.message-user {
  background-color: #007bff;
  color: white;
  margin-left: auto;
  text-align: right;
}

.message-assistant {
  background-color: #f1f3f5;
  color: #212529;
  margin-right: auto;
}

.message-assistant code {
  background-color: #e9ecef;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
}

.message-assistant strong {
  color: #dc3545;
}

.input-area {
  display: flex;
  gap: 8px;
  padding: 16px;
  border-top: 1px solid #dee2e6;
}

.input-area textarea,
.input-area input {
  flex: 1;
  padding: 8px 12px;
  border: 1px solid #dee2e6;
  border-radius: 4px;
  font-family: inherit;
}

.input-area button {
  padding: 8px 16px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-weight: 500;
}

.input-area button:hover:not(:disabled) {
  background-color: #0056b3;
}

.input-area button:disabled {
  background-color: #6c757d;
  cursor: not-allowed;
}
```

---

## API Response Time

Typical response times:

| Query Type | Time |
|-----------|------|
| Greeting | < 500ms |
| Real-world scenario | 1-3 seconds |
| CVE search | 2-5 seconds |
| Product analysis | 3-8 seconds |
| General question | 2-4 seconds |

For longer operations, show a loading spinner or typing indicator.

---

## Error Handling Checklist

- [ ] Check `response.statusCode` is 200
- [ ] Validate `response.data.response` is not empty
- [ ] Validate `response.data.sessionId` exists
- [ ] Handle network timeouts (set timeout to 30s minimum)
- [ ] Implement retry logic for failed requests
- [ ] Log errors for debugging
- [ ] Show user-friendly error messages

---

## Testing the Integration

### Manual Testing Checklist

- [ ] Send greeting message ("hi", "hello")
- [ ] Send real-world scenario question ("should i trust this email?")
- [ ] Send follow-up with context (keep same sessionId)
- [ ] Send CVE search ("CVE-2024-1234")
- [ ] Send product search ("OpenSSL vulnerabilities")
- [ ] Verify session persistence across requests
- [ ] Test on mobile (responsive design)
- [ ] Test long responses (>1000 chars)

### cURL Testing

```bash
# Test basic message
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"hi"}' | jq

# Test with context
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message":"Is this email safe?",
    "context":"From: admin@company.com"
  }' | jq

# Test help endpoint
curl http://localhost:3000/chat/help | jq '.response'
```

---

## Environment Configuration

Create a `.env.local` or `.env.development` file:

```env
REACT_APP_API_URL=http://localhost:3000
REACT_APP_API_TIMEOUT=30000
REACT_APP_SESSION_STORAGE_KEY=vuln-session
```

Then use in your app:

```typescript
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000';
const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT || '30000');

const client = axios.create({
  baseURL: API_URL,
  timeout: API_TIMEOUT,
});
```

---

## Live View

When the API is running:
- **Swagger UI**: `http://localhost:3000/api`
- **Chat API**: `POST http://localhost:3000/chat`
- **Help**: `GET http://localhost:3000/chat/help`

Swagger UI allows you to test all endpoints directly with visual documentation.

---

## Full API Documentation

For comprehensive API documentation, see [API.md](./API.md).

---

## Support Files

- **API.md** - Complete API reference
- **README.md** - Project overview
- **src/chatbot/dto/chat-request.dto.ts** - TypeScript interfaces
