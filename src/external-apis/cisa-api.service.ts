import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto } from '../vulnerability/dto/cve.dto';

@Injectable()
export class CisaApiService {
  private readonly logger = new Logger(CisaApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly CISA_KEV_API = 'https://services.cisa.gov/rest/json/cves';
  private readonly CACHE_TTL = 3600;

  constructor() {
    this.apiClient = axios.create({
      baseURL: 'https://services.cisa.gov',
      timeout: 10000,
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  async getKnownExploitedVulnerabilities(limit: number = 50): Promise<CVEDto[]> {
    const cacheKey = 'cisa:kev';
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for CISA KEV');
      return cached;
    }

    try {
      this.logger.log('Fetching CISA Known Exploited Vulnerabilities');
      const response = await this.apiClient.get('/rest/json/cves');

      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseCisaVulnerability(vuln, true))
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.error(`Error fetching CISA KEV: ${error}`);
      return [];
    }
  }

  async searchCisaAdvisories(productName: string, limit: number = 5): Promise<CVEDto[]> {
    const cacheKey = `cisa:search:${productName}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for CISA search: ${productName}`);
      return cached;
    }

    try {
      this.logger.log(`Searching CISA advisories for: ${productName}`);
      const response = await this.apiClient.get('/rest/json/cves', {
        params: {
          keyword: productName,
          limit,
        },
      });

      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseCisaVulnerability(vuln, true))
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.warn(`Error searching CISA advisories: ${error}`);
      return [];
    }
  }

  async getCisaAlerts(limit: number = 20): Promise<CVEDto[]> {
    const cacheKey = 'cisa:alerts';
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for CISA alerts');
      return cached;
    }

    try {
      this.logger.log('Fetching CISA Alerts');
      const response = await this.apiClient.get('/rest/json/alerts', {
        params: {
          limit,
        },
      });

      const alerts = (response.data?.alerts || [])
        .map((alert: any) => this.parseCisaAlert(alert))
        .slice(0, limit);

      this.cache.set(cacheKey, alerts);
      return alerts;
    } catch (error) {
      this.logger.warn(`Error fetching CISA alerts: ${error}`);
      return [];
    }
  }

  async getCriticalVulnerabilities(days: number = 30): Promise<CVEDto[]> {
    try {
      this.logger.log(`Fetching CISA critical vulnerabilities from last ${days} days`);
      
      // Get all KEV and filter by criticality and date
      const allVulns = await this.getKnownExploitedVulnerabilities(1000);
      
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - days);

      return allVulns.filter((vuln) => {
        const publishDate = new Date(vuln.publishedDate || '');
        return (
          publishDate >= cutoffDate &&
          (vuln.metrics?.cvssV31Severity === 'CRITICAL' ||
            vuln.metrics?.cvssV31Severity === 'HIGH')
        );
      }).slice(0, 20);
    } catch (error) {
      this.logger.error(`Error fetching critical vulnerabilities: ${error}`);
      return [];
    }
  }

  private parseCisaVulnerability(vuln: any, isExploited = true): CVEDto {
    return {
      id: vuln.cveID || vuln.id || 'UNKNOWN',
      publishedDate: vuln.dateAdded || vuln.publicDate,
      published: new Date(vuln.dateAdded || vuln.publicDate || '').getFullYear(),
      description: vuln.shortDescription || vuln.description || 'No description available',
      metrics: {
        cvssV31Score: vuln.cvssScore || vuln.cvssV3Score,
        cvssV31Severity: vuln.cvssScore ? this.getVulnerabilitySeverity(vuln.cvssScore) : 'UNKNOWN',
      },
      affectedProducts: vuln.affectedVendor
        ? [`${vuln.affectedVendor} ${vuln.affectedProduct}`.trim()]
        : [],
      references: [
        ...(vuln.notes || []).map((note: string) => ({
          url: note,
          source: 'CISA',
        })),
      ],
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
      isExploited,
    };
  }

  private parseCisaAlert(alert: any): CVEDto {
    return {
      id: alert.vulnerability || 'UNKNOWN',
      publishedDate: alert.dateAdded || new Date().toISOString(),
      published: new Date(alert.dateAdded || '').getFullYear(),
      description: alert.shortDescription || alert.description || 'Security alert',
      metrics: {
        cvssV31Severity: 'CRITICAL',
      },
      affectedProducts: [alert.affectedVendor, alert.affectedProduct].filter(Boolean),
      references: [
        {
          url: alert.sourceURL || '',
          source: 'CISA Alert',
        },
      ],
      isExploited: true,
    };
  }

  private getVulnerabilitySeverity(score: number): string {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('CISA API cache cleared');
  }
}
