import { Injectable, Logger } from '@nestjs/common';
import * as dns from 'dns';
import { promisify } from 'util';

const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);

export interface EmailValidation {
  isValid: boolean;
  domain: string;
  hasMXRecords: boolean;
  hasSpfRecord: boolean;
  hasDmarcRecord: boolean;
  suspicionLevel: 'safe' | 'suspicious' | 'dangerous';
  reasons: string[];
  suggestions: string[];
}

@Injectable()
export class EmailValidationService {
  private readonly logger = new Logger(EmailValidationService.name);
  private readonly suspiciousDomains = new Set([
    'secure-login', 'verify-account', 'confirm-identity', 'update-info',
    'alerts-alerts', '-alerts.com', '-secure.com', 'security-verify',
  ]);

  async validateEmailSender(email: string): Promise<EmailValidation> {
    this.logger.log(`Validating email sender: ${email}`);
    const [localPart, domain] = email.split('@');

    if (!domain) {
      return {
        isValid: false,
        domain: '',
        hasMXRecords: false,
        hasSpfRecord: false,
        hasDmarcRecord: false,
        suspicionLevel: 'dangerous',
        reasons: ['Invalid email format'],
        suggestions: ['Verify the email address is correct'],
      };
    }

    try {
      const [hasMX, spfRecord, dmarcRecord, suspicion] = await Promise.all([
        this.checkMXRecords(domain),
        this.checkSPFRecord(domain),
        this.checkDMARCRecord(domain),
        this.checkDomainSuspicion(domain),
      ]);

      const reasons: string[] = [];
      const suggestions: string[] = [];

      if (!hasMX) {
        reasons.push('Domain has no valid mail servers registered');
        suggestions.push('This is likely a fake domain. Be very careful.');
      }

      if (!spfRecord) {
        reasons.push('Domain has no SPF record (no email authentication)');
        suggestions.push('Legitimate companies use SPF for email authentication');
      }

      if (!dmarcRecord) {
        reasons.push('Domain has no DMARC policy (weak authentication)');
        suggestions.push('Legitimate companies implement DMARC for security');
      }

      if (suspicion.suspicious) {
        reasons.push(`Domain looks suspicious: ${suspicion.reason}`);
        suggestions.push('Be very careful with this email');
      }

      let suspicionLevel: 'safe' | 'suspicious' | 'dangerous' = 'safe';
      if (!hasMX || suspicion.dangerous) {
        suspicionLevel = 'dangerous';
      } else if (reasons.length > 0 || suspicion.suspicious) {
        suspicionLevel = 'suspicious';
      }

      return {
        isValid: hasMX,
        domain,
        hasMXRecords: hasMX,
        hasSpfRecord: spfRecord,
        hasDmarcRecord: dmarcRecord,
        suspicionLevel,
        reasons,
        suggestions,
      };
    } catch (error) {
      this.logger.error(`Error validating email ${email}: ${error}`);
      return {
        isValid: true, // Be conservative if DNS fails
        domain,
        hasMXRecords: false,
        hasSpfRecord: false,
        hasDmarcRecord: false,
        suspicionLevel: 'suspicious',
        reasons: ['Could not verify domain authentication'],
        suggestions: ['Contact the sender through official channels to verify'],
      };
    }
  }

  private async checkMXRecords(domain: string): Promise<boolean> {
    try {
      const mxRecords = await resolveMx(domain);
      return mxRecords && mxRecords.length > 0;
    } catch (error) {
      this.logger.debug(`No MX records for domain ${domain}`);
      return false;
    }
  }

  private async checkSPFRecord(domain: string): Promise<boolean> {
    try {
      const txtRecords = await resolveTxt(domain);
      return txtRecords.some((record: any[]) =>
        record.join('').startsWith('v=spf1'),
      );
    } catch (error) {
      this.logger.debug(`No SPF record for domain ${domain}`);
      return false;
    }
  }

  private async checkDMARCRecord(domain: string): Promise<boolean> {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const txtRecords = await resolveTxt(dmarcDomain);
      return txtRecords.some((record: any[]) =>
        record.join('').startsWith('v=DMARC1'),
      );
    } catch (error) {
      this.logger.debug(`No DMARC record for domain ${domain}`);
      return false;
    }
  }

  private checkDomainSuspicion(domain: string): { suspicious: boolean; dangerous: boolean; reason?: string } {
    const lowerDomain = domain.toLowerCase();

    // Check for obviously fake domains
    const dangerousPatterns = [
      /^[^.]*secure[^.]*login/,
      /^[^.]*verify[^.]*account/,
      /^[^.]*confirm[^.]*identity/,
      /paypal.*\.(?!com$)/,
      /amazon.*\.(?!com$)/,
      /apple.*\.(?!com$)/,
      /microsoft.*\.(?!com$)/,
      /google.*\.(?!com$)/,
      /bank.*\.(?!com$)/,
      /netflix.*\.(?!com$)/,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(lowerDomain)) {
        return {
          suspicious: true,
          dangerous: true,
          reason: 'Domain mimics a legitimate company',
        };
      }
    }

    // Check for suspicious patterns
    for (const suspicious of this.suspiciousDomains) {
      if (lowerDomain.includes(suspicious)) {
        return {
          suspicious: true,
          dangerous: false,
          reason: `Domain contains suspicious word: "${suspicious}"`,
        };
      }
    }

    // Check for new/fresh domains (too many hyphens, numbers)
    if ((lowerDomain.match(/-/g) || []).length > 2) {
      return {
        suspicious: true,
        dangerous: false,
        reason: 'Domain has unusual number of hyphens',
      };
    }

    return { suspicious: false, dangerous: false };
  }
}
