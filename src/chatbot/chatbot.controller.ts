import { Controller, Post, Body, Get } from '@nestjs/common';
import { ChatbotService } from './chatbot.service';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { ChatRequestDto, ChatResponseDto } from './dto/chat-request.dto';
import { randomUUID } from 'crypto';

@ApiTags('Security Analysis')
@Controller('chat')
export class ChatbotController {
  constructor(private readonly chatbotService: ChatbotService) {}

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
}