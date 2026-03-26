import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';

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

      // Check URLhaus database
      const result = await this.checkURLhaus(normalizedUrl, domain);

      // Cache the result
      this.cache.set(cacheKey, result);
      return result;
    } catch (error) {
      this.logger.error(`Error checking URL ${url}: ${error}`);
      return {
        url,
        domain: new URL(url.startsWith('http') ? url : 'https://' + url).hostname,
        isMalicious: false,
        detector: 'error',
        confidence: 'low',
        recommendations: ['Could not verify URL against threat databases'],
      };
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

    // Check all URLs
    const results = await Promise.all(uniqueUrls.map(url => this.checkUrl(url)));

    return results;
  }

  private async checkURLhaus(url: string, domain: string): Promise<MaliciousSiteCheckResult> {
    try {
      this.logger.log(`Checking URLhaus for: ${domain}`);

      // Check full URL
      let response = await axios.post(
        this.urlhausUrl,
        { url },
        { timeout: 5000 },
      ).catch(() => null);

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
      const domainCheck = await axios.post(
        this.urlhausHostUrl,
        { host: domain },
        { timeout: 5000 },
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

      const response = await axios.post(
        this.urlhausHostUrl,
        { host: domain },
        { timeout: 5000 },
      ).catch(() => null);

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
}
