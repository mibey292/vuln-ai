import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import * as https from 'https';
import { MaliciousSiteDetectionService } from './malicious-site-detection.service';

export interface WebsiteSecurityAnalysis {
  url: string;
  isReachable: boolean;
  hasSSL: boolean;
  sslGrade: string;
  redirectChain: string[];
  securityHeaders: Record<string, string>;
  suspiciousIndicators: string[];
  riskLevel: 'safe' | 'moderate' | 'suspicious' | 'dangerous';
  isMalicious?: boolean;
  maliciousThreat?: string;
  recommendations: string[];
}

@Injectable()
export class WebsiteAnalysisService {
  private readonly logger = new Logger(WebsiteAnalysisService.name);

  constructor(private readonly maliciousSiteDetection: MaliciousSiteDetectionService) {}

  async analyzeWebsite(url: string): Promise<WebsiteSecurityAnalysis> {
    this.logger.log(`Analyzing website: ${url}`);

    try {
      // Normalize URL
      let normalizedUrl = url;
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      const urlObj = new URL(normalizedUrl);
      const domain = urlObj.hostname;

      // Check if URL is known malicious (URLhaus)
      const maliciousCheckResult = await this.maliciousSiteDetection.checkUrl(normalizedUrl);

      // If it's known malicious, return immediately with high-severity warning
      if (maliciousCheckResult.isMalicious) {
        this.logger.warn(`⚠️ MALICIOUS SITE DETECTED: ${domain}`);
        return {
          url: normalizedUrl,
          isReachable: true,
          hasSSL: false,
          sslGrade: 'F',
          redirectChain: [],
          securityHeaders: {},
          suspiciousIndicators: [
            `🚨 KNOWN MALICIOUS SITE - ${maliciousCheckResult.threat?.type || 'malware'}`,
            `Threat Type: ${maliciousCheckResult.threat?.type || 'unknown'}`,
            `Status: ${maliciousCheckResult.threat?.status || 'Active threat'}`,
            'This URL/domain is in known malware/phishing databases',
          ],
          isMalicious: true,
          maliciousThreat: maliciousCheckResult.threat?.type,
          riskLevel: 'dangerous',
          recommendations: [
            '🚨 DO NOT CLICK THIS LINK',
            '🚨 DO NOT DOWNLOAD ANYTHING FROM THIS SITE',
            'This site is known to host malware or phishing content',
            'Report this email/link to your email provider immediately',
            'If this came from a trusted source, notify them their account may be compromised',
            'URLhaus Detection: ' + (maliciousCheckResult.threat?.status || 'Known threat'),
          ],
        };
      }

      // Check SSL/HTTPS
      const sslInfo = await this.checkSSL(urlObj);

      // Fetch headers
      const headers = await this.fetchSecurityHeaders(normalizedUrl);

      // Check for redirects
      const redirectChain = await this.checkRedirects(normalizedUrl);

      // Analyze domain suspicion
      const suspicious = this.checkDomainSuspicion(domain);

      // Overall risk assessment
      const riskLevel = this.calculateRiskLevel(sslInfo, headers, suspicious);

      // Generate recommendations
      const recommendations = this.generateRecommendations(sslInfo, headers, suspicious, riskLevel);

      return {
        url: normalizedUrl,
        isReachable: sslInfo.reachable,
        hasSSL: sslInfo.hasSSL,
        sslGrade: sslInfo.grade,
        redirectChain,
        securityHeaders: headers,
        suspiciousIndicators: suspicious,
        riskLevel,
        isMalicious: false,
        recommendations,
      };
    } catch (error) {
      this.logger.error(`Error analyzing website ${url}: ${error}`);
      return {
        url,
        isReachable: false,
        hasSSL: false,
        sslGrade: 'Unknown',
        redirectChain: [],
        securityHeaders: {},
        suspiciousIndicators: ['Website could not be reached'],
        riskLevel: 'suspicious',
        recommendations: [
          'Website may be offline or blocked',
          'Verify the URL is correct',
          'Be cautious if this is an unsolicited link',
        ],
      };
    }
  }

  private async checkSSL(urlObj: URL): Promise<{ reachable: boolean; hasSSL: boolean; grade: string }> {
    try {
      const isHttps = urlObj.protocol === 'https:';

      if (!isHttps) {
        return { reachable: true, hasSSL: false, grade: 'F' };
      }

      // Try to connect and check certificate
      const agent = new https.Agent({ rejectUnauthorized: false });
      const response = await axios.get(urlObj.toString(), {
        timeout: 5000,
        httpAgent: undefined,
        httpsAgent: agent,
        maxRedirects: 0,
      }).catch(err => {
        // Even 404/503 means it's reachable
        if (err.response) {
          return err.response;
        }
        throw err;
      });

      // Simple SSL grade based on connection success
      return { reachable: true, hasSSL: true, grade: 'A' };
    } catch (error) {
      this.logger.debug(`SSL check failed for ${urlObj.hostname}: ${error}`);
      return { reachable: false, hasSSL: false, grade: 'F' };
    }
  }

  private async fetchSecurityHeaders(url: string): Promise<Record<string, string>> {
    try {
      const response = await axios.head(url, {
        timeout: 5000,
        maxRedirects: 0,
        validateStatus: () => true, // Accept all statuses
      });

      const importantHeaders = [
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'strict-transport-security',
        'x-xss-protection',
        'referrer-policy',
      ];

      const headers: Record<string, string> = {};
      for (const header of importantHeaders) {
        if (response.headers[header]) {
          headers[header] = response.headers[header];
        }
      }

      return headers;
    } catch (error) {
      this.logger.debug(`Could not fetch headers for ${url}: ${error}`);
      return {};
    }
  }

  private async checkRedirects(url: string, maxRedirects: number = 5): Promise<string[]> {
    const chain: string[] = [url];

    try {
      for (let i = 0; i < maxRedirects; i++) {
        const response = await axios.get(chain[chain.length - 1], {
          timeout: 5000,
          maxRedirects: 0,
          validateStatus: (status) => (status >= 300 && status < 400) || status === 200,
        });

        if (response.status === 200) {
          break;
        }

        const redirectUrl = response.headers.location;
        if (!redirectUrl) {
          break;
        }

        const redirectFull = new URL(redirectUrl, chain[chain.length - 1]).toString();
        chain.push(redirectFull);
      }
    } catch (error) {
      this.logger.debug(`Could not check redirects: ${error}`);
    }

    return chain;
  }

  private checkDomainSuspicion(domain: string): string[] {
    const indicators: string[] = [];
    const lowerDomain = domain.toLowerCase();

    // Check for obviously fake domains
    const dangerousPatterns = [
      { pattern: /paypal/, name: 'PayPal' },
      { pattern: /amazon/, name: 'Amazon' },
      { pattern: /apple/, name: 'Apple' },
      { pattern: /microsoft/, name: 'Microsoft' },
      { pattern: /google/, name: 'Google' },
      { pattern: /^bank/, name: 'Bank' },
      { pattern: /netflix/, name: 'Netflix' },
    ];

    for (const { pattern, name } of dangerousPatterns) {
      if (pattern.test(lowerDomain) && !lowerDomain.includes(name.toLowerCase())) {
        indicators.push(`Domain impersonates ${name}`);
      }
    }

    // Check for suspicious patterns
    if (lowerDomain.includes('-secure')) indicators.push('Suspicious "-secure" in domain');
    if (lowerDomain.includes('-verify')) indicators.push('Suspicious "-verify" in domain');
    if (lowerDomain.includes('verify')) indicators.push('Domain contains "verify"');
    if (lowerDomain.includes('confirm')) indicators.push('Domain contains "confirm"');
    if (lowerDomain.includes('update')) indicators.push('Domain contains "update"');

    // Check for freshly registered domains (high hyphen count)
    if ((lowerDomain.match(/-/g) || []).length > 3) {
      indicators.push('Domain has unusual number of hyphens');
    }

    // Check for suspicious TLDs
    if (lowerDomain.match(/\.xyz$|\.tk$|\.ml$|\.ga$/)) {
      indicators.push('Using uncommon/free TLD');
    }

    // Check for long domains (often suspicious)
    if (domain.length > 30) {
      indicators.push('Domain name is unusually long');
    }

    return indicators;
  }

  private calculateRiskLevel(
    ssl: { reachable: boolean; hasSSL: boolean; grade: string },
    headers: Record<string, string>,
    suspicious: string[],
  ): 'safe' | 'moderate' | 'suspicious' | 'dangerous' {
    let risk = 0;

    if (!ssl.reachable) return 'suspicious';
    if (!ssl.hasSSL) risk += 2;
    if (Object.keys(headers).length === 0) risk += 1;
    risk += suspicious.length * 2;

    if (risk >= 6 || suspicious.length > 2) return 'dangerous';
    if (risk >= 3) return 'suspicious';
    if (risk >= 1) return 'moderate';
    return 'safe';
  }

  private generateRecommendations(
    ssl: { reachable: boolean; hasSSL: boolean; grade: string },
    headers: Record<string, string>,
    suspicious: string[],
    riskLevel: string,
  ): string[] {
    const recommendations: string[] = [];

    if (!ssl.hasSSL) {
      recommendations.push('Website does not use HTTPS (not encrypted) - Avoid entering sensitive data');
    }

    if (Object.keys(headers).length === 0) {
      recommendations.push('Website is missing security headers - Less protection against attacks');
    }

    if (riskLevel === 'dangerous') {
      recommendations.push('⚠️ This website shows significant warning signs. Do NOT enter personal information.');
      recommendations.push('Verify the website address is correct by visiting through a search engine');
    } else if (riskLevel === 'suspicious') {
      recommendations.push('This website has some concerning characteristics. Be cautious.');
      recommendations.push('Do not enter passwords or financial information unless you verify it\'s legitimate');
    }

    if (suspicious.length > 0) {
      recommendations.push(`Issues detected: ${suspicious.join(', ')}`);
    }

    if (riskLevel === 'safe') {
      recommendations.push('✅ Website appears legitimate. Standard security practices apply.');
    }

    return recommendations;
  }
}
