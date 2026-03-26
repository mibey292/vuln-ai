import { Injectable, Logger } from '@nestjs/common';
import OpenAI from 'openai';

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

@Injectable()
export class LlmService {
  private readonly logger = new Logger(LlmService.name);
  private openrouterClient: OpenAI;

  constructor() {
    const openrouterKey = process.env.OPENROUTER_API_KEY;

    if (openrouterKey) {
      this.logger.log('Using OpenRouter API');
      this.openrouterClient = new OpenAI({
        apiKey: openrouterKey,
        baseURL: 'https://openrouter.io/api/v1',
        defaultHeaders: {
          'HTTP-Referer': 'https://vulnai.local',
          'X-Title': 'VulnAI',
        },
      });
    } else {
      this.logger.error('OPENROUTER_API_KEY not configured. LLM features disabled.');
    }
  }

  isConfigured(): boolean {
    return !!this.openrouterClient;
  }

  async generateResponse(
    messages: LLMMessage[],
    systemPrompt?: string,
  ): Promise<string> {
    try {
      if (!this.isConfigured()) {
        this.logger.warn('LLM not configured, returning fallback response');
        return `I don't have natural language capabilities configured. Please set OPENROUTER_API_KEY in your .env file.`;
      }

      const allMessages: LLMMessage[] = [];
      
      if (systemPrompt) {
        allMessages.push({
          role: 'system',
          content: systemPrompt,
        });
      }
      
      allMessages.push(...messages);

      // Use OpenRouter models
      let response;
      try {
        response = await this.openrouterClient.chat.completions.create({
          model: 'gpt-4-turbo',
          messages: allMessages as OpenAI.Chat.ChatCompletionMessageParam[],
          temperature: 0.7,
          max_tokens: 2000,
        });
      } catch (error: any) {
        // Fallback to GPT-3.5 if GPT-4 fails
        this.logger.warn(`GPT-4 failed, trying GPT-3.5: ${error.message}`);
        try {
          response = await this.openrouterClient.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: allMessages as OpenAI.Chat.ChatCompletionMessageParam[],
            temperature: 0.7,
            max_tokens: 2000,
          });
        } catch (fallbackError: any) {
          this.logger.error(`Both models failed: ${fallbackError.message}`);
          throw fallbackError;
        }
      }

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error('No content in LLM response');
      }

      return content;
    } catch (error) {
      this.logger.error(`Error generating LLM response: ${error}`);
      throw error;
    }
  }

  async generateSecurityResponse(
    userMessage: string,
    vulnerabilityData: string,
    conversationHistory: LLMMessage[] = [],
  ): Promise<string> {
    const systemPrompt = `You are VulnAI, a professional cybersecurity vulnerability analysis assistant. 
Your role is to help users understand security vulnerabilities, their risks, and mitigation strategies.

Guidelines:
- Provide clear, concise explanations of technical security concepts
- Always prioritize critical security information
- Use markdown formatting for readability
- Be professional but conversational
- Reference CVE IDs, CVSS scores, and severity levels
- Suggest practical remediation steps
- Explain the business impact of vulnerabilities when relevant

Current vulnerability data context:
${vulnerabilityData}`;

    const messages: LLMMessage[] = [
      ...conversationHistory,
      {
        role: 'user',
        content: userMessage,
      },
    ];

    return this.generateResponse(messages, systemPrompt);
  }

  async enhanceVulnerabilityResponse(
    cveId: string,
    vulnerability: Record<string, any>,
    analysis: Record<string, any>,
  ): Promise<string> {
    const vulnerabilityJson = JSON.stringify(
      {
        id: cveId,
        description: vulnerability.description,
        severity: vulnerability.metrics?.cvssV31Severity,
        cvss_score: vulnerability.metrics?.cvssV31Score,
        affected_products: vulnerability.affectedProducts?.slice(0, 5),
        is_exploited: vulnerability.isExploited,
        references: vulnerability.references?.slice(0, 3),
      },
      null,
      2,
    );

    const analysisJson = JSON.stringify(analysis, null, 2);

    const prompt = `I have the following CVE data and analysis. Please provide a comprehensive but natural explanation:

CVE: ${cveId}
Data:
${vulnerabilityJson}

Analysis:
${analysisJson}

Please explain:
1. What this vulnerability is in plain terms
2. Who is affected
3. What are the risks
4. What should be done about it
5. Timeline urgency`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a cybersecurity expert. Explain this vulnerability assessment in a clear, professional, and conversational manner.',
    );
  }

  async generateThreatReport(
    threatData: Record<string, any>,
  ): Promise<string> {
    const threatJson = JSON.stringify(threatData, null, 2);

    const prompt = `Generate a comprehensive threat landscape report based on this data:

${threatJson}

Include:
1. Executive summary
2. Key findings
3. Risk assessment
4. Immediate action items
5. Recommended security posture improvements`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a security analyst. Create a professional threat assessment report.',
    );
  }

  async summarizeVulnerabilities(
    cves: Array<{ id: string; severity: string; cvssScore?: number }>,
  ): Promise<string> {
    const summary = cves
      .map((c) => `- ${c.id}: ${c.severity} (CVSS: ${c.cvssScore || 'N/A'})`)
      .join('\n');

    const prompt = `Summarize the following CVEs in a way that helps a technical team understand the priority:

${summary}

Provide:
1. Summary of findings
2. Grouped by criticality
3. Recommended patching strategy`;

    return this.generateResponse(
      [{ role: 'user', content: prompt }],
      'You are a security operations lead. Provide a concise summary for your team.',
    );
  }

  async generateSimpleSecurityResponse(
    userMessage: string,
    contextData: string,
    conversationHistory: LLMMessage[] = [],
    systemPrompt?: string,
  ): Promise<string> {
    const defaultSystemPrompt = `You are a helpful security advisor explaining security issues to someone who isn't a tech expert.
Your goal is to help them understand what to do about the issue in simple, everyday language.

IMPORTANT RULES:
- Explain like you're talking to a friend, not a technical document
- Avoid technical jargon (don't explain CVSS, attack vectors, exploitability, etc.)
- Focus on what they should do practical steps
- Be reassuring, not scary
- Use everyday examples they can understand
- Keep explanations short and actionable
- If mentioning CVEs or technical terms, briefly translate to plain English

Context about the issue:
${contextData}`;

    const messages: LLMMessage[] = [
      ...conversationHistory,
      {
        role: 'user',
        content: userMessage,
      },
    ];

    return this.generateResponse(messages, systemPrompt || defaultSystemPrompt);
  }
}
