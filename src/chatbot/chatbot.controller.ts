import { Controller, Post, Body, Get, Query } from '@nestjs/common';
import { ChatbotService } from './chatbot.service';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { ChatRequestDto, ChatResponseDto } from './dto/chat-request.dto';
import { randomUUID } from 'crypto';
import { BreachCheckService } from '../external-apis/breach-check.service';
import { EmailValidationService } from '../external-apis/email-validation.service';
import { WebsiteAnalysisService } from '../external-apis/website-analysis.service';
import { ThreatIntelligenceService } from '../analytics/threat-intelligence.service';

@ApiTags('Security Analysis')
@Controller('chat')
export class ChatbotController {
  constructor(
    private readonly chatbotService: ChatbotService,
    private readonly breachCheckService: BreachCheckService,
    private readonly emailValidationService: EmailValidationService,
    private readonly websiteAnalysisService: WebsiteAnalysisService,
    private readonly threatIntelligenceService: ThreatIntelligenceService,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Chat with VulnAI Security Assistant',
    description: `Send a message to analyze CVEs, products, threats, or ask real-world security questions.
    
Supports:
- **Real-world scenarios**: Ask about email safety, phishing, link safety, attachment safety, websites, social engineering, password breaches, and account security
- **CVE search**: Search for specific CVE IDs (e.g., "CVE-2024-1234")
- **Product vulnerabilities**: Check vulnerabilities for products (e.g., "OpenSSL vulnerabilities")
- **Threat analysis**: Analyze current threat landscape
- **General security questions**: Ask anything security-related

Session Management:
- Sessions are automatically created if sessionId is not provided
- Sessions persist for 30 minutes to maintain conversation context
- Provide the returned sessionId in subsequent requests to continue the conversation
- Context from previous messages is remembered and used for better responses`,
  })
  @ApiBody({
    type: ChatRequestDto,
    description: 'User message and optional context for the security assistant',
    examples: {
      newSessionGreeting: {
        summary: 'New user greeting (no session needed)',
        description: 'Start a new conversation',
        value: { message: 'Hi, I need help with security' },
      },
      emailTrustNewSession: {
        summary: 'Ask about email trust (new session)',
        description: 'First question in a conversation',
        value: {
          message: 'Is this email safe? It claims to be from my bank but the sender address looks weird',
          context: 'sender@bank-security-2024.com',
        },
      },
      emailTrustFollowUp: {
        summary: 'Follow-up question with session context',
        description: 'Continue previous conversation with the returned sessionId',
        value: {
          message: 'The email is asking me to click a link to verify my account',
          sessionId: 'session-550e8400-e29b-41d4-a716-446655440000',
          context: 'They say my account has suspicious activity',
        },
      },
      cveSearch: {
        summary: 'Search for a CVE',
        value: { message: 'CVE-2024-1234' },
      },
      productVulnerabilities: {
        summary: 'Check product vulnerabilities',
        value: { message: 'OpenSSL vulnerabilities' },
      },
      phishing: {
        summary: 'Check for phishing',
        value: {
          message: 'Is this email phishing?',
          context: 'It asks me to verify account details and has grammar errors',
        },
      },
      linkSafety: {
        summary: 'Check if a link is safe',
        value: {
          message: 'Can I click this link?',
          context: 'https://suspicious-domain.com/verify-account',
        },
      },
      attachmentSafety: {
        summary: 'Check if attachment is safe',
        value: {
          message: 'Is it safe to open this file?',
          context: 'PDF from unknown sender',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Security analysis response with session ID for conversation continuation',
    type: ChatResponseDto,
    schema: {
      example: {
        response: '⚠️ Security Concern Detected: Determining if an email from a company is legitimate...',
        sessionId: 'session-550e8400-e29b-41d4-a716-446655440000',
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request - message is required',
  })
  @ApiResponse({
    status: 500,
    description: 'Internal server error',
  })
  async chat(@Body() chatInputDto: ChatRequestDto): Promise<ChatResponseDto> {
    // Generate session ID if not provided
    const sessionId = chatInputDto.sessionId || `session-${randomUUID()}`;
    
    const response = await this.chatbotService.chat(
      sessionId,
      chatInputDto.message,
      chatInputDto.context,
    );
    
    return { response, sessionId };
  }

  @Get('help')
  @ApiOperation({
    summary: 'Get help on available commands',
    description: 'Returns a comprehensive guide on all available chatbot commands',
  })
  @ApiResponse({
    status: 200,
    description: 'Help message with available commands',
    type: ChatResponseDto,
  })
  getHelp(): ChatResponseDto {
    const response = this.chatbotService.getHelp();
    return { response, sessionId: '' };
  }

  @Post('analyze-website')
  @ApiOperation({
    summary: 'Analyze website security',
    description: 'Analyze a website for SSL/TLS, security headers, redirect chains, and suspicious domain indicators.',
  })
  @ApiBody({
    schema: {
      example: {
        url: 'https://example.com',
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Website security analysis results',
    schema: {
      example: {
        url: 'https://example.com',
        isReachable: true,
        hasSSL: true,
        sslGrade: 'A',
        securityHeaders: {
          'Strict-Transport-Security': 'max-age=31536000',
          'Content-Security-Policy': "default-src 'self'",
        },
        redirectChain: ['https://example.com'],
        suspiciousIndicators: [],
        riskLevel: 'safe',
        recommendations: ['Website appears secure'],
      },
    },
  })
  async analyzeWebsite(
    @Body() body: { url: string },
  ): Promise<{
    url: string;
    isReachable: boolean;
    hasSSL: boolean;
    sslGrade: string;
    securityHeaders: Record<string, string>;
    redirectChain: string[];
    suspiciousIndicators: string[];
    riskLevel: string;
    recommendations: string[];
  }> {
    return this.websiteAnalysisService.analyzeWebsite(body.url);
  }

  @Post('check-breach')
  @ApiOperation({
    summary: 'Check if email/username appears in known data breaches',
    description: 'Check haveibeenpwned.com database to see if an email address or username has been compromised in known breaches.',
  })
  @ApiBody({
    schema: {
      example: {
        email: 'user@example.com',
        username: 'johndoe',
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Breach check results',
    schema: {
      example: {
        found: true,
        plainLanguageWarning:
          '⚠️ WARNING: This email appears in 2 known data breaches. You should change your password immediately.',
        breaches: [
          {
            name: 'LinkedIn',
            breachDate: '2012-05-05',
            count: 6000000,
            description: 'LinkedIn User Data Breach',
          },
        ],
      },
    },
  })
  async checkBreach(
    @Body() body: { email?: string; username?: string },
  ): Promise<{
    found: boolean;
    plainLanguageWarning: string;
    breaches: any[];
  }> {
    const breaches: any[] = [];

    if (body.email) {
      const emailBreaches = await this.breachCheckService.checkEmail(
        body.email,
      );
      breaches.push(...emailBreaches);
    }

    if (body.username) {
      const usernameBreaches = await this.breachCheckService.checkUsername(
        body.username,
      );
      breaches.push(...usernameBreaches);
    }

    let plainLanguageWarning = '✅ Good news: Not found in major known breaches.';
    if (breaches.length > 0) {
      plainLanguageWarning = `⚠️ WARNING: This ${body.email ? 'email' : 'username'} appears in ${breaches.length} known data breach(es). You should change your password immediately and monitor your accounts for unusual activity.`;
    }

    return {
      found: breaches.length > 0,
      plainLanguageWarning,
      breaches,
    };
  }

  @Post('validate-email')
  @ApiOperation({
    summary: 'Validate email sender address',
    description:
      'Check if an email sender address is legitimate by validating DNS records (MX, SPF, DMARC) and detecting domain impersonation patterns.',
  })
  @ApiBody({
    schema: {
      example: {
        senderEmail: 'support@example.com',
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Email validation results',
    schema: {
      example: {
        email: 'support@example.com',
        isValid: true,
        domain: 'example.com',
        hasMXRecords: true,
        hasSpfRecord: true,
        hasDmarcRecord: false,
        suspicionLevel: 'safe',
        reasons: [],
        suggestions: ['Email appears legitimate'],
      },
    },
  })
  async validateEmail(
    @Body() body: { senderEmail: string },
  ): Promise<{
    email: string;
    isValid: boolean;
    domain: string;
    hasMXRecords: boolean;
    hasSpfRecord: boolean;
    hasDmarcRecord: boolean;
    suspicionLevel: string;
    reasons: string[];
    suggestions: string[];
  }> {
    const validation = await this.emailValidationService.validateEmailSender(
      body.senderEmail,
    );
    return {
      email: body.senderEmail,
      ...validation,
    };
  }

  @Get('threat-intelligence')
  @ApiOperation({
    summary: 'Get threat intelligence feed',
    description:
      'Get a non-technical threat intelligence feed with the latest critical vulnerabilities and security threats, in plain language for regular users.',
  })
  @ApiResponse({
    status: 200,
    description: 'Threat intelligence feed with plain language alerts',
    schema: {
      example: {
        lastUpdated: '2024-01-15T10:30:00Z',
        summaryForNonTechUsers:
          '• 3 critical vulnerabilities reported today affecting major software\n• Windows users should update immediately\n• Stay alert for phishing emails about these issues',
        criticalAlerts: [
          {
            plainLanguage:
              'Hackers could completely control your system. Update immediately.',
          },
        ],
        thisWeekVulnerabilities: [
          {
            title: 'Critical Security Update',
            plainLanguage: 'Important update available for your software.',
            urgency: 'This Week',
          },
        ],
        exploitedNow: [
          {
            title: 'Active Exploit',
            plainLanguage: 'Hackers are actively attacking. Update now.',
            urgency: 'Act Now',
          },
        ],
      },
    },
  })
  async getThreatIntelligence(): Promise<{
    lastUpdated: string;
    summaryForNonTechUsers: string;
    criticalAlerts: Array<{ plainLanguage: string }>;
    thisWeekVulnerabilities: Array<{
      title: string;
      plainLanguage: string;
      urgency: string;
    }>;
    exploitedNow: Array<{
      title: string;
      plainLanguage: string;
      urgency: string;
    }>;
  }> {
    return this.threatIntelligenceService.getThreatIntelligenceFeed();
  }
}