import { Injectable, Logger } from '@nestjs/common';
import { VulnerabilityService } from '../vulnerability/vulnerability.service';
import { RealWorldVulnerabilityService } from '../vulnerability/real-world-vulnerability.service';
import { ThreatAnalyzerService } from '../analytics/threat-analyzer.service';
import { RiskCalculatorService } from '../analytics/risk-calculator.service';
import { LlmService } from '../llm/llm.service';
import { SecurityRecommendationDto } from '../vulnerability/dto/cve.dto';
import NodeCache from 'node-cache';

@Injectable()
export class ChatbotService {
  private readonly logger = new Logger(ChatbotService.name);
  private conversationContext = new Map<string, any[]>();
  private sessionCache: NodeCache; // 30 minute TTL for sessions

  constructor(
    private readonly vulnerabilityService: VulnerabilityService,
    private readonly realWorldVulnService: RealWorldVulnerabilityService,
    private readonly threatAnalyzer: ThreatAnalyzerService,
    private readonly riskCalculator: RiskCalculatorService,
    private readonly llmService: LlmService,
  ) {
    this.sessionCache = new NodeCache({ stdTTL: 1800, checkperiod: 600 });
  }

  async chat(sessionId: string, message: string, context?: string): Promise<string> {
    try {
      this.logger.log(`Chat request for session ${sessionId}: ${message}`);
      
      const fullMessage = context ? `${message}\nContext: ${context}` : message;
      
      this.addToContext(sessionId, { role: 'user', content: fullMessage, timestamp: new Date() });
      this.sessionCache.set(sessionId, { lastActivity: new Date() });

      const lowerMessage = message.toLowerCase().trim();
      
      const greetingResponse = this.detectGreeting(lowerMessage);
      if (greetingResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: greetingResponse, timestamp: new Date() });
        return greetingResponse;
      }

      const maliciousResponse = this.detectMaliciousIntent(lowerMessage);
      if (maliciousResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: maliciousResponse, timestamp: new Date() });
        return maliciousResponse;
      }
      
      const realWorldScenario = await this.realWorldVulnService.analyzeRealWorldScenarioWithLLM(message);
      if (realWorldScenario) {
        const response = await this.handleRealWorldScenario(sessionId, message, realWorldScenario);
        this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
        return response;
      }

      if (this.isNonSecurityQuery(lowerMessage)) {
        const response = `I'm sorry I can't help with that\n I'm a security assistant focused on cybersecurity topics. I can help with:\n\n• Email and link safety\n• Phishing detection\n• File and attachment safety\n• Website legitimacy\n• Password security\n• CVE and vulnerability research\n\nDo you have any security questions I can help with?`;
        this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
        return response;
      }

      const vagueQueryResponse = this.detectVagueSecurityQuery(lowerMessage);
      if (vagueQueryResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: vagueQueryResponse, timestamp: new Date() });
        return vagueQueryResponse;
      }

      const yesNoResponse = this.detectYesNoResponse(lowerMessage, sessionId);
      if (yesNoResponse) {
        this.addToContext(sessionId, { role: 'assistant', content: yesNoResponse, timestamp: new Date() });
        return yesNoResponse;
      }

      const intent = this.detectSecurityIntent(lowerMessage);
      let response: string;

      switch (intent) {
        case 'cveSearch':
          response = await this.handleCVESearch(sessionId, message);
          break;
        case 'productVulnerability':
          response = await this.handleProductVulnerability(sessionId, message);
          break;
        case 'threatAnalysis':
          response = await this.handleThreatAnalysis(sessionId, message);
          break;
        case 'exploitedVulnerabilities':
          response = await this.handleExploitedVulnerabilities(sessionId);
          break;
        case 'recentVulnerabilities':
          response = await this.handleRecentVulnerabilities(sessionId);
          break;
        case 'dependencyScan':
          response = await this.handleDependencyScan(sessionId, message);
          break;
        case 'criticalAlerts':
          response = await this.handleCriticalAlerts(sessionId);
          break;
        case 'help':
          response = this.getHelpMessage();
          break;
        default:
          response = await this.handleGeneralSecurityQuery(sessionId, message);
      }

      this.addToContext(sessionId, { role: 'assistant', content: response, timestamp: new Date() });
      return response;
    } catch (error) {
      this.logger.error(`Error in chat: ${error}`);
      return `**Error:** Unable to process your request. Please try again later.`;
    }
  }

  private async handleCVESearch(sessionId: string, message: string): Promise<string> {
    // Extract CVE ID from message (e.g., CVE-2024-1234)
    const cveMatch = message.match(/CVE-\d{4}-\d{4,}/i);
    if (!cveMatch) {
      return `Please provide a CVE ID (e.g., CVE-2024-1234)`;
    }

    const cveId = cveMatch[0].toUpperCase();
    const cveData = await this.vulnerabilityService.getCVEDetails(cveId);

    if (!cveData) {
      return `❌ **CVE Not Found**: Could not find details for ${cveId}`;
    }

    // Get recommendation from risk calculator
    const recommendation = this.riskCalculator.generateRecommendation(cveData);

    // Prepare structured data for LLM
    const vulnerabilityContext = JSON.stringify(
      {
        cveId: cveData.id,
        description: cveData.description,
        severity: cveData.metrics?.cvssV31Severity,
        cvssScore: cveData.metrics?.cvssV31Score,
        affected: cveData.affectedProducts?.slice(0, 5),
        isExploited: cveData.isExploited,
        recommendation: recommendation.recommendation,
        additionalSteps: recommendation.additionalSteps,
        nvdUrl: cveData.nvdUrl,
      },
      null,
      2,
    );

    // Get conversation history for context
    const history = this.getContextMessages(sessionId, 3);

    try {
      // Use LLM to generate natural response
      const response = await this.llmService.generateSecurityResponse(
        `Analyze this CVE in detail: ${cveId}`,
        vulnerabilityContext,
        history,
      );

      // Append reference links
      return response + `\n\n🔗 [View on NVD](${cveData.nvdUrl})`;
    } catch (error) {
      this.logger.error(`LLM generation failed, falling back to template: ${error}`);
      // Fallback to template response if LLM fails
      return this.generateCVETemplateResponse(cveId, cveData, recommendation);
    }
  }

  private generateCVETemplateResponse(
    cveId: string,
    cveData: any,
    recommendation: SecurityRecommendationDto,
  ): string {
    let response = `✅ **${cveId} Analysis**\n\n`;
    response += `**📋 Description:**\n${cveData.description || 'N/A'}\n\n`;
    
    if (cveData.metrics?.cvssV31Score) {
      response += `**⚠️ Severity:**\n`;
      response += `• CVSS v3.1 Score: ${cveData.metrics.cvssV31Score}/10\n`;
      response += `• Severity: **${cveData.metrics.cvssV31Severity}**\n\n`;
    }

    if (cveData.affectedProducts && cveData.affectedProducts.length > 0) {
      response += `**🎯 Affected Products:**\n`;
      cveData.affectedProducts.slice(0, 5).forEach((product) => {
        response += `• ${product}\n`;
      });
      if (cveData.affectedProducts.length > 5) {
        response += `• ... and ${cveData.affectedProducts.length - 5} more\n`;
      }
      response += '\n';
    }

    if (cveData.isExploited) {
      response += `🚨 **KNOWN EXPLOITED VULNERABILITY** - Active exploitation detected\n\n`;
    }

    if (cveData.references && cveData.references.length > 0) {
      response += `**🔗 References:**\n`;
      cveData.references.slice(0, 3).forEach((ref, idx) => {
        response += `${idx + 1}. [${ref.source || 'Link'}](${ref.url})\n`;
      });
      response += '\n';
    }

    response += `**💡 Recommendation:**\n${recommendation.recommendation}\n`;
    if (recommendation.additionalSteps && recommendation.additionalSteps.length > 0) {
      response += `\n**Additional Steps:**\n`;
      recommendation.additionalSteps.forEach((step) => {
        response += `• ${step}\n`;
      });
    }

    response += `\n🔗 [View on NVD](${cveData.nvdUrl})`;
    return response;
  }

  private getContextMessages(sessionId: string, limit: number = 3): any[] {
    const context = this.conversationContext.get(sessionId) || [];
    const recentMessages = context.slice(-limit * 2).map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));
    return recentMessages;
  }

  private async handleProductVulnerability(sessionId: string, message: string): Promise<string> {
    // Extract product name - look for patterns like "product vulnerabilities" or "check product"
    const productMatch = message.match(/(?:for|in|product\s+|check\s+|analyze\s+)?([a-zA-Z0-9\s._-]+?)(?:\s+(?:vulnerabilities|cves|vulns|bugs)|$)/i);
    
    if (!productMatch || !productMatch[1].trim()) {
      return `Please specify a product name (e.g., "OpenSSL vulnerabilities" or "Apache vulnerabilities")`;
    }

    const productName = productMatch[1].trim();
    const vulnerabilities = await this.vulnerabilityService.getVulnerableProducts(productName, 10);

    if (vulnerabilities.length === 0) {
      return `❌ **No vulnerabilities found** for product: ${productName}`;
    }

    let response = `🔍 **Vulnerabilities for ${productName}**\n\n`;
    response += `Found: **${vulnerabilities.length}** vulnerabilities\n\n`;

    vulnerabilities.slice(0, 5).forEach((vuln) => {
      response += `**${vuln.id}** [${vuln.metrics?.cvssV31Severity || 'UNKNOWN'}]\n`;
      response += `• Score: ${vuln.metrics?.cvssV31Score || 'N/A'}/10\n`;
      if (vuln.affectedProducts && vuln.affectedProducts.length > 0) {
        response += `• Affected: ${vuln.affectedProducts[0]}\n`;
      }
      response += '\n';
    });

    const analysis = await this.vulnerabilityService.analyzeThreat(vulnerabilities);
    response += `**📊 Threat Analysis:**\n`;
    response += `• Threat Level: **${analysis.threatLevel.toUpperCase()}**\n`;
    response += `• Risk Score: ${analysis.riskScore}/100\n`;
    response += `• Exploitable CVEs: ${analysis.exploitableCount}\n\n`;

    response += `**🎯 Top Recommendations:**\n`;
    analysis.recommendations.slice(0, 3).forEach((rec) => {
      response += `• ${rec}\n`;
    });

    return response;
  }

  private async handleThreatAnalysis(sessionId: string, message: string): Promise<string> {
    // Get recent critical vulnerabilities for general threat analysis
    const criticalCves = await this.vulnerabilityService.getCriticalVulnerabilities(30);

    if (criticalCves.length === 0) {
      return `No critical vulnerabilities detected in the last 30 days.`;
    }

    const analysis = await this.vulnerabilityService.analyzeThreat(criticalCves.slice(0, 10));

    let response = `🛡️ **Threat Landscape Analysis (Last 30 Days)**\n\n`;
    response += `**📊 Overview:**\n`;
    response += `• Threat Level: **${analysis.threatLevel.toUpperCase()}**\n`;
    response += `• Aggregate Risk Score: ${analysis.riskScore}/100\n`;
    response += `• Critical CVEs Found: ${analysis.affectedCount}\n`;
    response += `• Known Exploited: ${analysis.exploitableCount}\n\n`;

    if (analysis.patterns.length > 0) {
      response += `**⚠️ Detected Patterns:**\n`;
      analysis.patterns.forEach((pattern) => {
        response += `• ${pattern}\n`;
      });
      response += '\n';
    }

    response += `**💡 Key Recommendations:**\n`;
    analysis.recommendations.slice(0, 5).forEach((rec) => {
      response += `• ${rec}\n`;
    });

    return response;
  }

  private async handleExploitedVulnerabilities(sessionId: string): Promise<string> {
    const exploitedCves = await this.vulnerabilityService.getKnownExploitedVulnerabilities(20);

    if (exploitedCves.length === 0) {
      return `No known exploited vulnerabilities currently tracked.`;
    }

    let response = `🚨 **Known Exploited Vulnerabilities**\n\n`;
    response += `Found: **${exploitedCves.length}** actively exploited CVEs\n\n`;

    const recommendations = await this.vulnerabilityService.getSecurityRecommendations(
      exploitedCves.slice(0, 5),
    );

    recommendations.forEach((rec, idx) => {
      response += `**${idx + 1}. ${rec.cveId}**\n`;
      response += `   Priority: **${rec.priority.toUpperCase()}**\n`;
      response += `   ${rec.recommendation}\n\n`;
    });

    response += `⚠️ **IMMEDIATE ACTION REQUIRED** - These vulnerabilities are actively being exploited`;

    return response;
  }

  private async handleRecentVulnerabilities(sessionId: string): Promise<string> {
    const recentCves = await this.vulnerabilityService.getRecentVulnerabilities(7, 15);

    if (recentCves.length === 0) {
      return `No new vulnerabilities published in the last 7 days.`;
    }

    let response = `📅 **Recent Vulnerabilities (Last 7 Days)**\n\n`;
    response += `Found: **${recentCves.length}** new CVEs\n\n`;

    const criticalCount = recentCves.filter((c) => c.metrics?.cvssV31Severity === 'CRITICAL').length;
    const highCount = recentCves.filter((c) => c.metrics?.cvssV31Severity === 'HIGH').length;

    response += `**📊 Breakdown:**\n`;
    response += `• Critical: ${criticalCount}\n`;
    response += `• High: ${highCount}\n`;
    response += `• Medium/Low: ${recentCves.length - criticalCount - highCount}\n\n`;

    response += `**Top Recent CVEs:**\n`;
    recentCves.slice(0, 5).forEach((cve) => {
      response += `• **${cve.id}** [${cve.metrics?.cvssV31Severity}] - ${cve.description?.substring(0, 80)}...\n`;
    });

    return response;
  }

  private async handleDependencyScan(sessionId: string, message: string): Promise<string> {
    return `**Dependency Scanning**\n\n📦 To scan dependencies, please provide a package.json file or list dependencies.\n\nExample: "Scan npm dependencies: express@4.17.1, lodash@4.17.21"\n\nWill check for vulnerabilities in:\n• npm (Node.js)\n• pip (Python)\n• Maven (Java)\n• Cargo (Rust)`;
  }

  private async handleCriticalAlerts(sessionId: string): Promise<string> {
    const criticalCves = await this.vulnerabilityService.getCriticalVulnerabilities(7);

    if (criticalCves.length === 0) {
      return `✅ No critical alerts from the past 7 days.`;
    }

    let response = `🚨 **CRITICAL SECURITY ALERTS**\n\n`;
    response += `⚠️ **${criticalCves.length}** Critical vulnerabilities detected\n\n`;

    criticalCves.slice(0, 3).forEach((cve) => {
      response += `**${cve.id}**\n`;
      response += `• Severity: **CRITICAL**\n`;
      response += `• Published: ${new Date(cve.publishedDate || '').toLocaleDateString()}\n`;
      if (cve.isExploited) {
        response += `• Status: 🔴 **ACTIVELY EXPLOITED**\n`;
      }
      response += '\n';
    });

    response += `**🎯 IMMEDIATE ACTIONS REQUIRED:**\n`;
    response += `1. Identify affected systems in your environment\n`;
    response += `2. Check vendor security advisories\n`;
    response += `3. Plan emergency patching if applicable\n`;
    response += `4. Implement compensating controls\n`;
    response += `5. Monitor for exploitation attempts`;

    return response;
  }

  private async handleGeneralSecurityQuery(sessionId: string, message: string): Promise<string> {
    // Search for vulnerabilities based on the message
    const searchResults = await this.vulnerabilityService.searchVulnerabilities(message, 5);

    if (searchResults.length === 0) {
      // Use LLM to answer general security questions
      const history = this.getContextMessages(sessionId, 2);
      try {
        const response = await this.llmService.generateSecurityResponse(
          message,
          'No specific CVE data matched your query. Please provide general cybersecurity guidance.',
          history,
        );
        return response;
      } catch (error) {
        this.logger.error(`LLM generation failed: ${error}`);
        return `**Search Results:** No vulnerabilities found matching your query "${message}".\n\nTry:\n• Searching for a specific CVE ID (e.g., "CVE-2024-1234")\n• Asking about a product (e.g., "OpenSSL vulnerabilities")\n• Type "help" for more options`;
      }
    }

    // Format search results for LLM
    const resultsContext = searchResults
      .map((r) => `- ${r.id} [${r.metrics?.cvssV31Severity}] CVSS: ${r.metrics?.cvssV31Score || 'N/A'}`)
      .join('\n');

    const history = this.getContextMessages(sessionId, 2);

    try {
      const response = await this.llmService.generateSecurityResponse(
        message,
        `Matching CVEs found:\n${resultsContext}`,
        history,
      );
      return response;
    } catch (error) {
      this.logger.error(`LLM generation failed, using template: ${error}`);
      // Fallback to template
      let response = `🔍 **Search Results for "${message}"**\n\n`;
      searchResults.slice(0, 5).forEach((result) => {
        response += `• **${result.id}** [${result.metrics?.cvssV31Severity || 'UNKNOWN'}]\n`;
        response += `  ${result.description?.substring(0, 100) || 'N/A'}...\n\n`;
      });
      response += `Type a specific CVE ID for detailed analysis.`;
      return response;
    }
  }

  private getHelpMessage(): string {
    let help = `**🛡️ VulnAI Security Assistant - Help Guide**\n\n`;
    
    help += `**📱 Real-World Security Questions (Non-Technical)**\n\n`;
    help += `Ask about everyday security concerns in plain language:\n\n`;
    
    help += `**1. Email Safety**\n`;
    help += `   Examples: "Should I trust this email?", "Is this email safe?", "Can I reply with my password?"\n`;
    help += `   I'll explain if the email looks suspicious and what to do.\n\n`;
    
    help += `**2. Phishing Detection**\n`;
    help += `   Examples: "Is this phishing?", "This email asks for my password usually how it's sent"\n`;
    help += `   I'll help you spot warning signs.\n\n`;
    
    help += `**3. Link Safety**\n`;
    help += `   Examples: "Is this link safe?", "Should I click this?", "Can I trust this URL?"\n`;
    help += `   I'll let you know if it seems suspicious.\n\n`;
    
    help += `**4. Attachment Safety**\n`;
    help += `   Examples: "Is it safe to open this file?", "Should I download this?"\n`;
    help += `   Tips on suspicious attachments.\n\n`;
    
    help += `**5. Website Trust**\n`;
    help += `   Examples: "Is this website legitimate?", "Should I buy from here?", "Is it a fake site?"\n`;
    help += `   I'll help you verify website legitimacy.\n\n`;
    
    help += `**6. Account Security**\n`;
    help += `   Examples: "My password was leaked, what should I do?", "I got a suspicious login alert"\n`;
    help += `   Practical steps to protect your account.\n\n`;
    
    help += `**7. Social Engineering**\n`;
    help += `   Examples: "Someone is asking weird questions about my job", "This message seems off"\n`;
    help += `   Learn to recognize manipulation attempts.\n\n`;
    
    help += `---\n\n`;
    help += `**🔍 Technical Vulnerability Queries**\n\n`;
    help += `Search for CVEs and technical vulnerabilities:\n\n`;
    
    help += `**1. Search CVE**\n`;
    help += `   Examples: "CVE-2024-1234", "Show details for CVE-2024-1234"\n`;
    help += `   Shows: Description, CVSS score, affected products, remediation\n\n`;
    
    help += `**2. Product Vulnerabilities**\n`;
    help += `   Examples: "OpenSSL vulnerabilities", "Apache CVEs", "Check MySQL"\n`;
    help += `   Shows: All CVEs for the product, threat analysis, recommendations\n\n`;
    
    help += `**3. Threat Analysis**\n`;
    help += `   Examples: "Analyze threats", "Threat landscape", "Current threats"\n`;
    help += `   Shows: Threat level, risk score, detected patterns\n\n`;
    
    help += `**4. Exploited Vulnerabilities**\n`;
    help += `   Examples: "Known exploited vulnerabilities", "Show actively exploited CVEs"\n`;
    help += `   Shows: CVEs with active exploitation, remediation priorities\n\n`;
    
    help += `**5. Recent CVEs**\n`;
    help += `   Examples: "Recent vulnerabilities", "New CVEs this week"\n`;
    help += `   Shows: Latest published vulnerabilities\n\n`;
    
    help += `**6. Critical Alerts**\n`;
    help += `   Examples: "Critical alerts", "Show critical vulnerabilities"\n`;
    help += `   Shows: Critical vulnerabilities from the last 7 days\n\n`;
    
    help += `**7. General Search**\n`;
    help += `   Just ask about any vulnerability or security topic\n\n`;
    
    help += `---\n\n`;
    help += `**💡 Tips:**\n`;
    help += `• For real-world questions, be as specific as possible (what does the email say?)\n`;
    help += `• For technical queries, mention product names or CVE IDs\n`;
    help += `• I'll explain everything in simple language you can understand\n\n`;
    
    help += `**Need specific help?** Ask your question and I'll assist!`;
    
    return help;
  }

  getHelp(): string {
    return this.getHelpMessage();
  }

  private async handleRealWorldScenario(
    sessionId: string,
    message: string,
    scenario: any,
  ): Promise<string> {
    this.logger.log(`Handling real-world scenario: ${scenario.type}`);

    try {
      // Get detailed CVE information for the related CVEs
      const cveDetails = await Promise.all(
        scenario.relatedCVEs.map((cveId: string) =>
          this.vulnerabilityService.getCVEDetails(cveId).catch(() => null),
        ),
      );

      const validCveDetails = cveDetails.filter((d) => d !== null);

      // Build context for LLM with simple language
      let cveContext = '';
      if (validCveDetails.length > 0) {
        cveContext = validCveDetails
          .map((cve) => {
            return `CVE: ${cve.id}
Severity: ${cve.metrics?.cvssV31Severity || 'Unknown'}
Score: ${cve.metrics?.cvssV31Score || 'N/A'}/10
Description: ${cve.description?.substring(0, 200) || 'N/A'}`;
          })
          .join('\n\n');
      }

      // Create simple language prompt for LLM
      const systemPrompt = scenario.type === 'phishing' 
        ? `You are a security advisor warning someone about a phishing email. Be DIRECT and CLEAR:
- Start by saying "This looks like a phishing email because..."
- List 2-3 specific red flags you see (from the warning signs provided)
- Explain why each red flag is suspicious in simple terms
- Give clear action steps to take immediately
- Be confident and direct, not vague
- Use everyday language, avoid technical jargon
- Make it clear this is a real threat they should take seriously`
        : `You are a helpful security advisor explaining potential security issues to someone who isn't a tech expert. 
Your goal is to help them understand the risk in simple, non-technical terms.
Focus on:
- What the problem is in plain language
- Why it matters to them
- What they should do about it
- Be practical and reassuring, not scary or technical
- Avoid technical jargon like CVE IDs, CVSS scores, attack vectors, etc.
- Use everyday examples they can relate to`;

      const userContext = `
The user asked about: "${message}"

This relates to: ${scenario.description}

Warning signs to look for:
${scenario.indicators.map((ind: string) => `- ${ind}`).join('\n')}

Potential risks:
${scenario.relatedCVEs.map((cveId: string) => `- ${cveId}`).join('\n')}

Risk level: ${scenario.riskLevel}

What they should do:
${scenario.recommendations.map((rec: string) => `- ${rec}`).join('\n')}

${cveContext ? `\nTechnical details (for reference):\n${cveContext}` : ''}
`;

      const history = this.getContextMessages(sessionId, 2);

      const llmResponse = await this.llmService.generateSimpleSecurityResponse(
        message,
        userContext,
        history,
        systemPrompt,
      );

      // Add CVE and risk information to the response
      let finalResponse = llmResponse;
      
      // For phishing, don't add technical CVE info - just use the LLM response with action steps
      if (scenario.type === 'phishing') {
        finalResponse += `\n\n**⚠️ This is a serious threat. Take these steps immediately:**\n`;
        scenario.recommendations.slice(0, 4).forEach((rec: string, idx: number) => {
          finalResponse += `${idx + 1}. ${rec}\n`;
        });
      } else {
        // For other scenarios, show summary with CVEs if available
        finalResponse += `\n\n**Summary:**\n`;
        finalResponse += `• Type of Issue: ${scenario.description}\n`;
        finalResponse += `• Risk Level: **${scenario.riskLevel.toUpperCase()}**\n`;
        if (scenario.relatedCVEs.length > 0) {
          finalResponse += `• Related Official CVEs: ${scenario.relatedCVEs.join(', ')}\n`;
        }
        finalResponse += `\n**📋 Action Steps:**\n`;
        scenario.recommendations.slice(0, 3).forEach((rec: string, idx: number) => {
          finalResponse += `${idx + 1}. ${rec}\n`;
        });
      }
      
      // Add follow-up suggestions
      const followUp = this.getFollowUpSuggestions(scenario.type);
      finalResponse += `\n**${followUp}**`;

      return finalResponse;
    } catch (error) {
      this.logger.error(`Error handling real-world scenario: ${error}`);

      // Fallback response if LLM fails
      let response = '';
      
      if (scenario.type === 'phishing') {
        response = `**⚠️ This looks like a phishing email**\n\n`;
        response += `**Red flags:**\n`;
        scenario.indicators.slice(0, 3).forEach((ind: string) => {
          response += `• ${ind}\n`;
        });
        response += `\n**What to do immediately:**\n`;
        scenario.recommendations.slice(0, 4).forEach((rec: string, idx: number) => {
          response += `${idx + 1}. ${rec}\n`;
        });
      } else {
        response = `**${scenario.description}**\n\n`;
        response += `**Watch out for:**\n`;
        scenario.indicators.slice(0, 3).forEach((ind: string) => {
          response += `• ${ind}\n`;
        });
        response += `\n**What you should do:**\n`;
        scenario.recommendations.slice(0, 3).forEach((rec: string, idx: number) => {
          response += `${idx + 1}. ${rec}\n`;
        });
        if (scenario.relatedCVEs.length > 0) {
          response += `\n**More info:** These issues are related to: ${scenario.relatedCVEs.join(', ')}\n`;
        }
      }
      
      // Add follow-up suggestions
      const followUp = this.getFollowUpSuggestions(scenario.type);
      response += `\n**${followUp}**`;

      return response;
    }
  }

  private detectSecurityIntent(message: string): string {
    const lowerMessage = message.toLowerCase();

    // CVE Search
    if (lowerMessage.match(/cve-?\d{4}-?\d{4,}/) || lowerMessage.includes('cve')) {
      return 'cveSearch';
    }

    // Product Vulnerabilities
    if (
      lowerMessage.includes('vulnerabilities') ||
      lowerMessage.includes('vuln') ||
      lowerMessage.includes('cves') ||
      lowerMessage.match(/check\s+\w+|analyze\s+\w+/)
    ) {
      return 'productVulnerability';
    }

    // Threat Analysis
    if (
      lowerMessage.includes('threat') ||
      lowerMessage.includes('analyze') ||
      lowerMessage.includes('landscape') ||
      lowerMessage.includes('pattern')
    ) {
      return 'threatAnalysis';
    }

    // Exploited vulnerabilities
    if (
      lowerMessage.includes('exploit') ||
      lowerMessage.includes('actively exploited')
    ) {
      return 'exploitedVulnerabilities';
    }

    // Recent vulnerabilities
    if (
      lowerMessage.includes('recent') ||
      lowerMessage.includes('new') ||
      lowerMessage.includes('latest')
    ) {
      return 'recentVulnerabilities';
    }

    // Dependency scanning
    if (
      lowerMessage.includes('dependency') ||
      lowerMessage.includes('dependencies') ||
      lowerMessage.includes('package') ||
      lowerMessage.includes('npm') ||
      lowerMessage.includes('pip')
    ) {
      return 'dependencyScan';
    }

    // Critical alerts
    if (
      lowerMessage.includes('critical') ||
      lowerMessage.includes('alert') ||
      lowerMessage.includes('urgent')
    ) {
      return 'criticalAlerts';
    }

    // Help
    if (
      lowerMessage.includes('help') ||
      lowerMessage.includes('how') ||
      lowerMessage.includes('what can you')
    ) {
      return 'help';
    }

    return 'generalSearch';
  }

  private detectGreeting(message: string): string | null {
    const lowerMessage = message.toLowerCase().trim();

    // Detect greetings
    if (
      lowerMessage === 'hi' ||
      lowerMessage === 'hello' ||
      lowerMessage === 'hey' ||
      lowerMessage === 'greetings' ||
      lowerMessage === 'yo' ||
      lowerMessage === 'howdy' ||
      lowerMessage === 'good morning' ||
      lowerMessage === 'good afternoon' ||
      lowerMessage === 'good evening'
    ) {
      return `👋 **Welcome to VulnAI Security Assistant!**

I'm here to help you with security questions. I can assist with:

**For everyday security concerns** (simple language):
- "Should I trust this email?"
- "Is this link safe to click?"
- "Is it safe to open this file?"
- "Should I buy from this website?"

**For technical security information**:
- "CVE-2024-1234" (search for CVE details)
- "OpenSSL vulnerabilities" (check product security)
- "Recent CVEs" (see latest vulnerabilities)

Type "help" for detailed information about all available commands, or just ask your question and I'll guide you!`;
    }

    // Detect when user needs help
    if (
      lowerMessage === 'help me' ||
      lowerMessage === 'i need help' ||
      lowerMessage === "what can you do" ||
      lowerMessage === 'what can i ask you' ||
      lowerMessage === 'what are you'
    ) {
      return this.getHelpMessage();
    }

    return null;
  }

  private isNonSecurityQuery(message: string): boolean {
    // List of non-security related keywords
    const nonSecurityKeywords = [
      'shopping', 'buy', 'pizza', 'food', 'restaurant', 'movie', 'music', 'game',
      'sports', 'weather', 'travel', 'recipe', 'cooking', 'dating', 'love',
      'joke', 'tell me a', 'what is the', 'how many', 'when was', 'who is',
      'what\'s the capital', 'what time', 'what day', 'current time', 'calculation',
      'math problem', 'solve this', 'translate', 'definition', 'meaning',
    ];

    // Check if message contains non-security keywords
    for (const keyword of nonSecurityKeywords) {
      if (message.includes(keyword)) {
        return true;
      }
    }

    // If message is less than 10 chars and doesn't contain security words, likely not security related
    if (message.length < 10 && !this.hasSecurityKeywords(message)) {
      return false; // Let it through to general query handler
    }

    return false;
  }

  private hasSecurityKeywords(message: string): boolean {
    const securityKeywords = [
      'email', 'password', 'secure', 'hack', 'virus', 'malware', 'phishing',
      'link', 'url', 'attachment', 'file', 'trust', 'cve', 'vulnerability',
      'attack', 'risk', 'threat', 'safe', 'breach', 'data', 'encrypt',
    ];

    return securityKeywords.some(keyword => message.includes(keyword));
  }

  private detectMaliciousIntent(message: string): string | null {
    // Detect requests for help with illegal/harmful activities
    const maliciousPatterns = [
      /\b(hack|hacking|hacked)\b/i,
      /\b(crack|cracking)\b/i,
      /\b(break into|brute force)\b/i,
      /\b(exploit|exploiting)\b.*\b(system|website|server|account)\b/i,
      /\b(attack|attacking)\b.*\b(website|server|system)\b/i,
      /\b(compromise|compromising)\b/i,
      /\b(gain access|unauthorized access|illegal access)\b/i,
      /\b(bypass|bypass security)\b/i,
    ];

    for (const pattern of maliciousPatterns) {
      if (pattern.test(message)) {
        return `I can't help with that. I'm designed to assist with defensive security and helping you protect yourself, not with hacking or attacking systems.\n\nIf you're interested in cybersecurity education, I'd be happy to help with:\n• Understanding how to protect your own systems\n• Learning about common vulnerabilities and how to defend against them\n• Security best practices for your accounts and devices`;
      }
    }

    return null;
  }

  private detectVagueSecurityQuery(message: string): string | null {
    // Detect vague security-related queries that need clarification
    const vaguePatterns = [
      { pattern: /someone\s+(sent|sent me|contacted|messaged)/i, suggestion: 'I\'d like to help! Could you tell me more?\n\n• Is this an email, text message, or social media message?\n• What did they ask or say?\n• Do you recognize this person?\n\nWith more details, I can better advise if it\'s safe.' },
      { pattern: /someone\s+(sent me\s+)?a\s+(message|text)/i, suggestion: 'I\'d like to help! Could you tell me more?\n\n• Is this an email, text message, or social media message?\n• What did they ask or say?\n• Do you recognize this person?\n\nWith more details, I can better advise if it\'s safe.' },
      { pattern: /got\s+a\s+(message|email|text)/i, suggestion: 'I can help with that! Could you share:\n\n• What type of message? (email, text, social media, etc.)\n• What\'s it about or asking you to do?\n• Who did it come from?\n\nMore details will help me give you better advice.' },
      { pattern: /is\s+it\s+safe/i, suggestion: 'I can help! Could you tell me more about:\n\n• What are you asking about? (Email, link, attachment, website, etc.)\n• What specifically are you unsure about?\n\nThe more details, the better advice I can give.' },
      { pattern: /should\s+i\s+/i, suggestion: 'I can help! Could you be more specific:\n\n• What exactly is the situation?\n• Is it about an email, link, file, or something else?\n• What are you worried might happen?\n\nWith more context, I can give you clearer guidance.' },
    ];

    for (const { pattern, suggestion } of vaguePatterns) {
      if (pattern.test(message)) {
        return suggestion;
      }
    }

    return null;
  }

  private detectYesNoResponse(message: string, sessionId: string): string | null {
    // Detect simple yes/no responses
    const yesPatterns = [
      /^\s*(yes|yeah|yep|sure|ok|okay|please|go ahead|do it)\s*$/i,
      /^\s*(i do|i would|i want|i'd like)\s*$/i,
    ];
    
    const noPatterns = [
      /^\s*(no|nope|nah|not now|later|skip)\s*$/i,
    ];

    const isYes = yesPatterns.some(pattern => pattern.test(message));
    const isNo = noPatterns.some(pattern => pattern.test(message));

    if (!isYes && !isNo) {
      return null;
    }

    // Get conversation history to find the last assistant message
    const history = this.conversationContext.get(sessionId) || [];
    
    // Find the last assistant message
    let lastAssistantMessage = null;
    for (let i = history.length - 1; i >= 0; i--) {
      if (history[i].role === 'assistant') {
        lastAssistantMessage = history[i].content;
        break;
      }
    }

    if (!lastAssistantMessage) {
      return null;
    }

    // Check if last message ended with a follow-up suggestion
    const followUpMatch = lastAssistantMessage.match(/💡 Next: (.+?)\?/i);
    if (!followUpMatch) {
      return null;
    }

    if (isNo) {
      return `No problem! Feel free to ask me anything else about security.`;
    }

    // Match the follow-up to the scenario type and provide contextual response
    const followUpText = followUpMatch[1]?.toLowerCase() || '';

    if (followUpText.includes('report') && followUpText.includes('phishing')) {
      return `**How to Report Phishing:**

**To your email provider:**
1. Open the phishing email (don't click links!)
2. Look for "Report spam" or "Report phishing" button
3. Click and follow the prompts
4. Most providers also let you mark as junk/spam

**To official authorities:**
• Forward the email to: **abuse@paypal.com** (for PayPal phishing)
• Report to: **ic3.gov** (Internet Crime Complaint Center - FBI)
• Report to: **reportphishing.apple.com** (if it's Apple phishing)
• Report to: **phishing@ia.gov** (US government phishing)

**To the real company:**
• Contact their official support using a phone number from their real website (NOT from the email)
• Tell them about the phishing attempt so they can warn other customers

**Enable protection:**
• Set up email filters/rules to catch similar emails
• Enable 2-factor authentication on important accounts
• Install browser security extensions

Reporting helps protect other people from the same attack!`;
    }

    if (followUpText.includes('checklist') && followUpText.includes('email')) {
      return `**Email Legitimacy Checklist:**

**Sender Information:**
☐ Email domain matches the company's official website (e.g., @paypal.com, not @paypal-alerts.com)
☐ Sender name matches what you expect
☐ You can verify the sender by contacting the company directly

**Content Clues:**
☐ Email greets you by name (not "Dear Customer")
☐ Specific details about your account or transaction
☐ Professional formatting and official branding
☐ Grammar and spelling are correct
☐ No unusual urgency or threats

**Links & Attachments:**
☐ Hover over links - they match the official website
☐ No suspicious attachments or requests to download
☐ Links use HTTPS and official domain names

**Request Type:**
☐ Legitimate companies rarely ask for passwords via email
☐ Banks don't ask for credit card numbers by email
☐ No requests for verification codes or 2FA tokens via email

**When in doubt:**
✓ Go directly to the company's website (type it yourself)
✓ Call the company's official phone number
✓ Check your account portal directly
✓ Never click links in suspicious emails

If you spot even one red flag, it's probably not legitimate!`;
    }

    if (followUpText.includes('safely check') && followUpText.includes('link')) {
      return `**How to Safely Check Links:**

**Before Clicking:**
1. **Hover over the link** - see where it actually goes (not just what text shows)
2. **Look at the URL** - does it match the website it claims to be from?
3. **Check for HTTPS** - make sure it has a lock icon 🔒

**Suspicious Link Red Flags:**
❌ URL doesn't match the company (e.g., link says "paypal.com" but goes to "pay-pal-secure.xyz")
❌ Shortened URLs (bit.ly, tinyurl, etc.) hiding the real destination
❌ Unusual ports or IP addresses instead of domain names
❌ Misspelled domains (e.g., "paypa1.com" instead of "paypal.com")

**Safe Ways to Check:**
1. **Don't click it** - Instead, go directly to the official website
2. Use a **URL checker tool**: 
   - virustotal.com (check if the link is flagged)
   - urlscan.io (see what the website looks like)
3. **Check the domain registrant**: whois.com (look up who owns the domain)
4. **Use browser extensions** that warn about phishing links

**Best Practice:**
Instead of clicking email links, always:
✓ Go to the official website directly
✓ Log in to your account manually
✓ Check your account portal for messages

This way, you're 100% sure you're on the real site!`;
    }

    if (followUpText.includes('scan') && followUpText.includes('file')) {
      return `**How to Safely Scan Files Before Opening:**

**Online Scanners (Safest):**
1. **VirusTotal.com**
   - Upload file or drag & drop
   - 70+ antivirus engines scan it
   - Shows if it's malicious
   
2. **URLhaus** (for suspicious URLs)
   - Checks if URL is known malware distributor

3. **Windows Defender online** (Microsoft safety)
   - Online file scanner from Microsoft

**On Your Computer:**
1. **Windows Defender** (built-in)
   - Right-click file → "Scan with Windows Defender"
   
2. **Antivirus Software**
   - Run a full scan with your antivirus
   - Kaspersky, Norton, McAfee, etc.

**Email Attachment Safety:**
✓ If you didn't expect the attachment → don't open
✓ Check with the sender: "Did you send me this file?"
✓ Suspicious file types to avoid: .exe, .zip, .scr, .bat, .docm

**Common Phishing Attachments:**
❌ .EXE files (programs)
❌ .ZIP files (hidden files inside)
❌ Macro-enabled documents (.DOCM, .XLSM)
❌ Scripts (.VBS, .JS)

**If You Already Opened It:**
1. Immediately scan WITH antivirus
2. Change important passwords (especially email)
3. Check your accounts for unauthorized activity
4. Enable 2-factor authentication if not already enabled

**Pro Tip:** 
Most email providers can scan attachments automatically. Enable these settings!`;
    }

    if (followUpText.includes('verify') && followUpText.includes('website')) {
      return `**How to Verify a Website is Real Before Shopping:**

**Domain & Address:**
☐ Official website matches what Google shows (search the company name)
☐ Domain looks normal (not strange variations like "amaz0n.com" or "amaz-on.com")
☐ Uses HTTPS with a lock 🔒 icon in address bar
☐ Company address and phone are displayed

**Business Information:**
☐ About Us page explains the business
☐ Real company history (not just started yesterday)
☐ Physical address you can verify
☐ Customer reviews on independent sites (Trustpilot, BBB)
☐ Social media accounts with followers and regular posts

**Security Indicators:**
☐ Privacy policy and terms clearly stated
☐ Secure payment options (not asking for wire transfer)
☐ Return policy is clear and fair
☐ Contact information (email, phone, chat support)

**Price & Offer Red Flags:**
❌ Prices WAY too good to be true
❌ Limited-time "exclusive" offers designed to rush you
❌ Requesting unusual payment methods (gift cards, cryptocurrency)
❌ No way to contact customer service

**Before You Buy:**
1. Search: "[Company Name] + scam" or "[Company Name] + reviews"
2. Check BBB.org (Better Business Bureau)
3. Look for verified seller badges
4. Start with a small test purchase if unsure
5. Use credit card (more fraud protection) not debit

**If Unsure:**
✓ Buy directly from the official store/website
✓ Use established marketplaces (Amazon, eBay - with seller ratings)
✓ Check the company on Better Business Bureau
✓ Ask friends if they've shopped there before

Stay safe and trust your gut!`;
    }

    if (followUpText.includes('social engineering')) {
      return `**Common Social Engineering Tactics to Watch For:**

**Phishing (Email/Text):**
- Fake urgent emails asking you to "verify" or "confirm"
- Claiming account suspension or suspicious activity
- Links to fake login pages
- Requests for passwords or personal info

**Pretexting (Phone Calls):**
- Scammers pretend to be from your bank, IT support, etc.
- "We detected fraud on your account"
- "We need to verify your identity"
- They ask for account numbers, passwords, or send money

**Baiting:**
- USB drives left in parking lots with malware
- Free software/apps with hidden infections
- "Click here to claim your prize!"

**Quid Pro Quo:**
- "Help me fix my computer, I'll give you X"
- "Answer these questions for a reward"
- Actually they're just collecting your personal info

**More Recent Tactics:**
- Fake Discord/Telegram groups
- Social media impersonation ("your friend" needs money)
- Deepfake videos (fake CEO asking for urgent wire transfer)

**How to Protect Yourself:**
✓ Never share passwords, PINs, or 2FA codes - legitimate companies never ask
✓ Verify by hanging up and calling the official number (not from email/text)
✓ Take time to think - don't rush decisions under pressure
✓ If something feels off, it probably is
✓ Enable multi-factor authentication (2FA) everywhere
✓ Check with trusted people before clicking/opening anything

**Red Flags:**
❌ Urgent "act now" messaging
❌ Requests for sensitive info
❌ Too good to be true offers
❌ Threats of account closure
❌ Asking you to keep it secret

When in doubt, ask someone you trust!`;
    }

    if (followUpText.includes('password') && followUpText.includes('leaked')) {
      return `**How to Check If Your Password Was Leaked:**

**Online Tools:**
1. **Have I Been Pwned (hibp.cc)**
   - Enter your email address
   - Shows if your data appeared in known breaches
   - Free and trusted by security pros

2. **Firefox Monitor (monitor.firefox.com)**
   - Same data as Have I Been Pwned
   - Sets up alerts for future breaches

3. **Google Password Manager**
   - checkup.google.com (password security checkup)
   - Shows compromised passwords

**What To Do If Your Password Was Leaked:**

**Immediately:**
1. Change your password to something NEW and STRONG
2. Use a different password than other accounts
3. Enable 2-factor authentication (2FA) on that account

**After That:**
4. Check other accounts - if you reused that password anywhere, change it
5. Monitor your account for suspicious activity
6. Consider a password manager (Bitwarden, 1Password, etc.)

**Create Strong Passwords:**
✓ At least 12 characters (longer is better)
✓ Mix of: uppercase, lowercase, numbers, symbols
✓ Not your name, birthday, or common words
✓ Completely unique for each account
✓ Example: "Tr0pical!Sunset#2024" (avoid dictionary patterns)

**Password Manager (Highly Recommended):**
- Stores all passwords securely
- Generates strong passwords for you
- No need to remember them
- Options: Bitwarden (free), 1Password, Dashlane

**Check If You're At Risk:**
1. Do you use the same password on multiple sites? ⚠️ Change all of them!
2. Haven't changed password in a year? ⚠️ Change it!
3. Password is over a year old? ⚠️ Change it!

Remember: Passwords found in breaches can be used to attack your accounts!`;
    }

    if (followUpText.includes('password') && followUpText.includes('security')) {
      return `**Password Security Checklist:**

**Create Strong Passwords:**
☐ At least 12-16 characters (longer = safer)
☐ Mix of uppercase, lowercase, numbers, symbols
☐ No common words, names, or birthdates
☐ Completely unique per account
☐ Use a password manager to generate them

**Protect Your Passwords:**
☐ Never share passwords via email, text, or chat
☐ Don't write them down on paper
☐ Don't tell anyone your password (not even friends)
☐ Never use passwords on public/shared computers
☐ Log out after using accounts (especially on shared devices)

**Account Security:**
☐ Enable 2-factor authentication (2FA) everywhere possible
☐ Use authenticator apps (Google Authenticator, Authy) - better than SMS
☐ Keep backup codes for important accounts in a safe place
☐ Check login activity regularly
☐ Remove old connected devices/apps

**Monitor Your Accounts:**
☐ Check login history regularly
☐ Review which apps have access to your accounts
☐ Remove access for apps you no longer use
☐ Set up email alerts for account changes
☐ Monitor for suspicious activity

**If Compromised:**
☐ Change password immediately from a safe device
☐ Enable 2FA if not already there
☐ Review account activity for unauthorized access
☐ Check for unauthorized profile changes
☐ Alert your bank if financial accounts involved

**Password Manager Setup:**
☐ Choose a reputable one (Bitwarden, 1Password, Dashlane, etc.)
☐ Create ONE strong master password
☐ Let it generate complex passwords for each site
☐ Let it auto-fill passwords (safer than typing)
☐ Store backup codes securely

**Best Practices:**
✓ Change passwords after breaches
✓ Change important accounts (email, banking) every 3 months
✓ Use different passwords for different accounts
✓ Keep software and OS updated
✓ Use antivirus/antimalware software

Your master password is crucial - make it VERY strong!`;
    }

    // Default response if no match found
    return `Thanks for your interest! Feel free to ask me any other security questions.`;
  }

  private getFollowUpSuggestions(scenarioType: string): string {
    const suggestions: Record<string, string> = {
      phishing: '💡 Next: Would you like to know how to report this phishing attempt?',
      email_trust: '💡 Next: Want a checklist to verify if a company email is legitimate?',
      link_safety: '💡 Next: Would you like tips on how to safely check where a link actually goes?',
      attachment_safety: '💡 Next: Want to know how to safely scan files before opening them?',
      website_trust: '💡 Next: Would you like to know how to verify if a website is real before shopping?',
      social_engineering: '💡 Next: Want to learn common social engineering tactics to watch out for?',
      password_breach: '💡 Next: Would you like to know how to check if your password was leaked?',
      account_security: '💡 Next: Want a step-by-step password security checklist?',
    };

    return suggestions[scenarioType] || '💡 Next: Ask me anything about security and I\'ll help!';
  }

  resetConversation(sessionId: string): void {
    this.conversationContext.delete(sessionId);
    this.logger.log(`Conversation reset for session ${sessionId}`);
  }

  private addToContext(sessionId: string, message: any): void {
    if (!this.conversationContext.has(sessionId)) {
      this.conversationContext.set(sessionId, []);
    }
    const context = this.conversationContext.get(sessionId);
    if (context) {
      context.push(message);
      if (context.length > 10) {
        context.shift();
      }
    }
  }
}
