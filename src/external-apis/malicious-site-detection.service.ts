import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { URLSearchParams } from 'url';

export interface MaliciousSiteCheckResult {
  url: string;
  domain: string;
  isMalicious: boolean;
  threat?: {
    type: 'malware' | 'phishing' | 'spam' | 'defacement' | 'exploit' | 'unknown';
    firstSeen?: string;
    lastSeen?: string;
    sources?: string[];
    status?: string;
  };
  detector: string; // Which service detected it
  confidence: 'high' | 'medium' | 'low';
  recommendations?: string[];
}

@Injectable()
export class MaliciousSiteDetectionService {
  private readonly logger = new Logger(MaliciousSiteDetectionService.name);
  private cache: NodeCache;
  // URLhaus v1 API endpoints
  private urlhausUrl = 'https://urlhaus-api.abuse.ch/v1/url/';
  private urlhausHostUrl = 'https://urlhaus-api.abuse.ch/v1/host/';

  constructor() {
    // Cache results for 24 hours
    this.cache = new NodeCache({ stdTTL: 86400, checkperiod: 3600 });
  }

  async checkUrl(url: string): Promise<MaliciousSiteCheckResult> {
    try {
      // Normalize URL
      let normalizedUrl = url;
      if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
        normalizedUrl = 'https://' + normalizedUrl;
      }

      const urlObj = new URL(normalizedUrl);
      const domain = urlObj.hostname;

      // Check cache first
      const cacheKey = `malicious_${domain}`;
      const cached = this.cache.get<MaliciousSiteCheckResult>(cacheKey);
      if (cached) {
        this.logger.debug(`Cache hit for ${domain}`);
        return cached;
      }

      // Try URLhaus database first
      const urlhausResult = await this.checkURLhaus(normalizedUrl, domain);
      
      // If URLhaus detects malicious, return immediately
      if (urlhausResult.isMalicious) {
        this.cache.set(cacheKey, urlhausResult);
        return urlhausResult;
      }

      // If URLhaus failed or is unavailable, try heuristic detection
      const heuristicResult = this.checkUrlHeuristics(normalizedUrl);
      if (heuristicResult.isMalicious) {
        this.logger.log(`Heuristic detection flagged: ${domain} as ${heuristicResult.threat?.type}`);
        this.cache.set(cacheKey, heuristicResult);
        return heuristicResult;
      }

      // URLhaus thought it was safe and heuristics agree - return URLhaus result
      this.cache.set(cacheKey, urlhausResult);
      return urlhausResult;
    } catch (error) {
      this.logger.error(`Error checking URL ${url}: ${error}`);
      // Fall back to heuristics on critical error
      const heuristicResult = this.checkUrlHeuristics(url);
      return heuristicResult;
    }
  }

  async checkDomain(domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      const cacheKey = `malicious_domain_${domain}`;
      const cached = this.cache.get<MaliciousSiteCheckResult>(cacheKey);
      if (cached) {
        this.logger.debug(`Cache hit for domain ${domain}`);
        return cached;
      }

      const result = await this.checkURLhausDomain(domain);
      this.cache.set(cacheKey, result);
      return result;
    } catch (error) {
      this.logger.error(`Error checking domain ${domain}: ${error}`);
      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'error',
        confidence: 'low',
      };
    }
  }

  /**
   * Extract all URLs from text and check them
   */
  async checkLinksInContent(content: string): Promise<MaliciousSiteCheckResult[]> {
    const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]*)/g;
    const matches = content.match(urlRegex) || [];

    if (matches.length === 0) {
      this.logger.debug('No URLs found in content');
      return [];
    }

    this.logger.log(`Found ${matches.length} URLs in content, checking them...`);

    // Remove duplicates
    const uniqueUrls = [...new Set(matches)];

    // Check all URLs against URLhaus
    const results = await Promise.all(uniqueUrls.map(url => this.checkUrl(url)));

    return results;
  }

  /**
   * Check domain reputation based on characteristics
   */
  private async checkURLhaus(url: string, domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      this.logger.log(`Checking URLhaus for: ${domain}`);

      // Check full URL using form data with auth key in URL path
      const params = new URLSearchParams();
      params.append('url', url);

      let response = await axios.post(
        this.urlhausUrl,
        params,
        {
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      ).catch((error) => {
        this.logger.warn(`URLhaus URL check error for ${url}: ${error.response?.status || error.message}`);
        return null;
      });

      if (!response) {
        this.logger.debug(`URLhaus returned null response for ${domain}`);
        return {
          url,
          domain,
          isMalicious: false,
          detector: 'URLhaus (API error)',
          confidence: 'low',
          recommendations: ['Could not verify URL against URLhaus (API temporarily unavailable)'],
        };
      }

      if (response?.data?.query_status === 'ok' && response?.data?.result) {
        const result = response.data.result[0];

        if (result.threat) {
          this.logger.warn(`Malicious site detected: ${domain} - Threat: ${result.threat}`);

          return {
            url,
            domain,
            isMalicious: true,
            threat: {
              type: this.mapThreatType(result.threat),
              firstSeen: result.date_added,
              lastSeen: result.last_seen,
              status: result.url_status,
            },
            detector: 'URLhaus',
            confidence: 'high',
            recommendations: [
              '🚨 This URL is known to host malware or phishing content',
              'Do NOT click this link',
              'Do NOT download anything from this site',
              'Report the email sender',
              'If this is a legitimate service, notify them immediately',
            ],
          };
        }
      }

      // Check domain if URL check didn't find anything
      const domainParams = new URLSearchParams();
      domainParams.append('host', domain);

      const domainCheck = await axios.post(
        this.urlhausHostUrl,
        domainParams,
        { 
          timeout: 5000,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      ).catch(() => null);

      if (domainCheck?.data?.query_status === 'ok' && domainCheck?.data?.urls?.length > 0) {
        const outcomes = domainCheck.data.urls.map((u: any) => u.threat || 'unknown');
        const threatCount = outcomes.filter((t: string) => t !== 'clean').length;

        if (threatCount > 0) {
          this.logger.warn(`Domain ${domain} has ${threatCount} malicious URLs`);

          return {
            url,
            domain,
            isMalicious: true,
            threat: {
              type: 'malware',
              status: `${threatCount} malicious URLs found on this domain`,
            },
            detector: 'URLhaus Domain Check',
            confidence: 'high',
            recommendations: [
              '⚠️ This domain has been used to host malware',
              'Be extremely cautious with any content from this sender',
              'Do not download or click links from this domain',
            ],
          };
        }
      }

      // If we get here, URL is clean
      this.logger.debug(`${domain} is not in URLhaus threat database`);
      return {
        url,
        domain,
        isMalicious: false,
        detector: 'URLhaus',
        confidence: 'high',
        recommendations: ['URL is not in URLhaus threat database'],
      };
    } catch (error) {
      this.logger.error(`URLhaus check failed for ${domain}: ${error}`);
      return {
        url,
        domain,
        isMalicious: false,
        detector: 'URLhaus (error)',
        confidence: 'low',
        recommendations: ['Could not verify against URLhaus threat database'],
      };
    }
  }

  private async checkURLhausDomain(domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      this.logger.log(`Checking URLhaus domain: ${domain}`);

      const params = new URLSearchParams();
      params.append('host', domain);

      const response = await axios.post(
        this.urlhausHostUrl,
        params,
        {
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      ).catch((error) => {
        this.logger.warn(`URLhaus domain check error for ${domain}: ${error.response?.status || error.message}`);
        return null;
      });

      if (!response) {
        this.logger.debug(`URLhaus returned null response for domain ${domain}`);
        return {
          url: domain,
          domain,
          isMalicious: false,
          detector: 'URLhaus (API error)',
          confidence: 'low',
        };
      }

      if (response?.data?.query_status === 'ok' && response?.data?.urls?.length > 0) {
        const urls = response.data.urls;
        const threatUrls = urls.filter((u: any) => u.threat !== 'clean');

        if (threatUrls.length > 0) {
          this.logger.warn(`Domain ${domain} has ${threatUrls.length} malicious URLs`);

          return {
            url: domain,
            domain,
            isMalicious: true,
            threat: {
              type: 'malware',
              status: `${threatUrls.length} malicious URLs found on this domain`,
              sources: threatUrls.map((u: any) => u.threat),
            },
            detector: 'URLhaus',
            confidence: 'high',
            recommendations: [
              '⚠️ This domain has hosted malicious content',
              'Do not click links from this domain',
              'Verify sender authenticity',
            ],
          };
        }
      }

      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'URLhaus',
        confidence: 'high',
      };
    } catch (error) {
      this.logger.error(`URLhaus domain check failed for ${domain}: ${error}`);
      return {
        url: domain,
        domain,
        isMalicious: false,
        detector: 'URLhaus (error)',
        confidence: 'low',
      };
    }
  }

  private mapThreatType(threat: string): 'malware' | 'phishing' | 'spam' | 'defacement' | 'exploit' | 'unknown' {
    const threatLower = threat.toLowerCase();

    if (threatLower.includes('phishing')) return 'phishing';
    if (threatLower.includes('malware')) return 'malware';
    if (threatLower.includes('spam')) return 'spam';
    if (threatLower.includes('defacement')) return 'defacement';
    if (threatLower.includes('exploit')) return 'exploit';

    return 'unknown';
  }

  /**
   * Heuristic-based malicious URL detection (fallback when URLhaus unavailable)
   */
  private checkUrlHeuristics(url: string): MaliciousSiteCheckResult {
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname || url;
      const pathname = urlObj.pathname || '';

      // Malicious patterns detected by heuristics
      const suspiciousPatterns = [
        // Fake security/verification domains
        { pattern: /paypal.*verify|verify.*paypal/i, threat: 'phishing', reason: 'Fake PayPal verification' },
        { pattern: /amazon.*verify|verify.*amazon/i, threat: 'phishing', reason: 'Fake Amazon verification' },
        { pattern: /apple.*verify|verify.*apple/i, threat: 'phishing', reason: 'Fake Apple verification' },
        { pattern: /microsoft.*verify|verify.*microsoft/i, threat: 'phishing', reason: 'Fake Microsoft verification' },
        { pattern: /google.*verify|verify.*google/i, threat: 'phishing', reason: 'Fake Google verification' },
        { pattern: /bank.*verify|verify.*bank/i, threat: 'phishing', reason: 'Fake bank verification' },
        { pattern: /confirm.*account|account.*confirm/i, threat: 'phishing', reason: 'Account confirmation phishing' },
        { pattern: /suspicious.*activity|activity.*suspended/i, threat: 'phishing', reason: 'Suspended account phishing' },
        { pattern: /update.*payment|payment.*update/i, threat: 'phishing', reason: 'Payment update phishing' },

        // Free hosting domains with malware history
        { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/i, threat: 'malware', reason: 'Known malware-prone TLD' },

        // Lookalike domains (typosquatting)
        { pattern: /rn-9gle|goog1e|gmail-security|paypa1/i, threat: 'phishing', reason: 'Lookalike domain (typosquatting)' },

        // Suspicious subdomains
        { pattern: /^secure-login-|^verify-account-|^confirm-identity-/i, threat: 'phishing', reason: 'Suspicious subdomain' },

        // Redirect/shortened URL services (high risk)
        { pattern: /bit\.ly|tinyurl|short\.link|go\.link/i, threat: 'unknown', reason: 'Shortened URL (unable to verify destination)' },
      ];

      // Check against patterns
      const fullUrl = domain + pathname;
      for (const { pattern, threat, reason } of suspiciousPatterns) {
        if (pattern.test(fullUrl)) {
          return {
            url,
            domain,
            isMalicious: true,
            threat: {
              type: threat as any,
              status: reason,
            },
            detector: 'Heuristic Analysis',
            confidence: 'medium',
            recommendations: [
              `⚠️ ${reason}`,
              'Do not click this link',
              'Do not enter credentials on this site',
              'Report to your email provider',
            ],
          };
        }
      }

      // Check domain reputation based on patterns
      const domainSuspicion = this.checkDomainReputation(domain);
      if (domainSuspicion.isSuspicious) {
        return {
          url,
          domain,
          isMalicious: true,
          threat: {
            type: 'phishing',
            status: domainSuspicion.reason,
          },
          detector: 'Domain Analysis',
          confidence: 'medium',
          recommendations: [
            `⚠️ ${domainSuspicion.reason}`,
            'Be cautious with this domain',
            'Verify sender authenticity',
          ],
        };
      }

      // URL passed heuristic checks
      return {
        url,
        domain,
        isMalicious: false,
        detector: 'Heuristic Analysis',
        confidence: 'medium',
        recommendations: ['URL passed basic security checks'],
      };
    } catch (error) {
      this.logger.debug(`Heuristic check failed for ${url}: ${error}`);
      return {
        url,
        domain: url,
        isMalicious: false,
        detector: 'Heuristic (error)',
        confidence: 'low',
      };
    }
  }

  /**
   * Check domain reputation based on characteristics
   */
  private checkDomainReputation(domain: string): { isSuspicious: boolean; reason: string } {
    const lowerDomain = domain.toLowerCase();

    // Check for extreme hyphens (indicates freshly registered domain)
    const hyphenCount = (lowerDomain.match(/-/g) || []).length;
    if (hyphenCount > 4) {
      return { isSuspicious: true, reason: 'Domain has excessive hyphens (likely fresh malicious domain)' };
    }

    // Check for numeric domains (very suspicious)
    if (/^\d+\.\d+/.test(lowerDomain)) {
      return { isSuspicious: true, reason: 'Numeric IP address domain (high bypass indicator)' };
    }

    // Check for very long domains (often malicious)
    if (lowerDomain.length > 40) {
      return { isSuspicious: true, reason: 'Domain name is unusually long' };
    }

    // Check for mixed case (bypass detection technique)
    if (/[a-z]/.test(domain) && /[A-Z]/.test(domain)) {
      return { isSuspicious: true, reason: 'Mixed case domain (potential bypass technique)' };
    }

    return { isSuspicious: false, reason: '' };
  }
}
