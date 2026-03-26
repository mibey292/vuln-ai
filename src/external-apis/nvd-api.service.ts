import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto, CVEMetrics, CVEReference } from '../vulnerability/dto/cve.dto';

@Injectable()
export class NvdApiService {
  private readonly logger = new Logger(NvdApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  private readonly CACHE_TTL = 3600; // 1 hour

  constructor() {
    this.apiClient = axios.create({
      baseURL: this.NVD_BASE_URL,
      timeout: 10000,
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  async getCVEById(cveId: string): Promise<CVEDto | null> {
    const cacheKey = `nvd:${cveId}`;
    const cached = this.cache.get<CVEDto>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for ${cveId}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching CVE ${cveId} from NVD`);
      const response = await this.apiClient.get(``, {
        params: {
          keywordSearch: cveId,
        },
      });

      const cve = this.parseNvdResponse(response.data);
      if (cve) {
        this.cache.set(cacheKey, cve);
        return cve;
      }
      return null;
    } catch (error) {
      this.logger.error(`Error fetching CVE ${cveId}: ${error}`);
      return null;
    }
  }

  async searchCVEs(query: string, limit: number = 5): Promise<CVEDto[]> {
    const cacheKey = `nvd:search:${query}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for search: ${query}`);
      return cached;
    }

    try {
      this.logger.log(`Searching NVD for: ${query}`);
      const response = await this.apiClient.get(``, {
        params: {
          keywordSearch: query,
          resultsPerPage: limit,
        },
      });

      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.error(`Error searching NVD for ${query}: ${error}`);
      return [];
    }
  }

  async getCVEsByProduct(productName: string, limit: number = 10): Promise<CVEDto[]> {
    const cacheKey = `nvd:product:${productName}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for product: ${productName}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching CVEs for product: ${productName}`);
      const response = await this.apiClient.get(``, {
        params: {
          cpeName: `cpe:2.3:*:*:${productName}:*:*:*:*:*:*:*:*`,
          resultsPerPage: limit,
        },
      });

      const cves = (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .slice(0, limit);

      this.cache.set(cacheKey, cves);
      return cves;
    } catch (error) {
      this.logger.error(`Error fetching CVEs for product ${productName}: ${error}`);
      return [];
    }
  }

  async getRecentCVEs(days: number = 7, limit: number = 20): Promise<CVEDto[]> {
    try {
      const dateStart = new Date();
      dateStart.setDate(dateStart.getDate() - days);
      const dateString = dateStart.toISOString().split('T')[0];

      this.logger.log(`Fetching CVEs from last ${days} days`);
      const response = await this.apiClient.get(``, {
        params: {
          pubStartDate: `${dateString}T00:00:00Z`,
          resultsPerPage: limit,
        },
      });

      return (response.data?.vulnerabilities || [])
        .map((vuln: any) => this.parseNvdVulnerability(vuln))
        .slice(0, limit);
    } catch (error) {
      this.logger.error(`Error fetching recent CVEs: ${error}`);
      return [];
    }
  }

  private parseNvdResponse(data: any): CVEDto | null {
    if (!data?.vulnerabilities || data.vulnerabilities.length === 0) {
      return null;
    }
    return this.parseNvdVulnerability(data.vulnerabilities[0]);
  }

  private parseNvdVulnerability(vuln: any): CVEDto {
    const cveData = vuln?.cve || {};
    const metrics = cveData?.metrics || {};
    const cvssV31 = metrics?.cvssMetricV31?.[0]?.cvssData || {};

    return {
      id: cveData?.id || 'UNKNOWN',
      publishedDate: cveData?.published || new Date().toISOString(),
      published: new Date(cveData?.published || '').getFullYear(),
      description: cveData?.descriptions?.[0]?.value || 'No description available',
      metrics: {
        cvssV31Score: cvssV31?.baseScore,
        cvssV31Severity: cvssV31?.baseSeverity,
      },
      affectedProducts: this.extractAffectedProducts(cveData?.configurations),
      references: (cveData?.references || []).map((ref: any) => ({
        url: ref.url,
        source: ref.source,
        tags: ref.tags,
      })),
      nvdUrl: `https://nvd.nist.gov/vuln/detail/${cveData?.id}`,
      isExploited: this.checkIfExploited(cveData?.id),
    };
  }

  private extractAffectedProducts(configurations: any[]): string[] {
    const products: Set<string> = new Set();
    
    if (!configurations || !Array.isArray(configurations)) {
      return [];
    }

    configurations.forEach((config: any) => {
      if (config?.nodes && Array.isArray(config.nodes)) {
        config.nodes.forEach((node: any) => {
          if (node?.cpeMatch && Array.isArray(node.cpeMatch)) {
            node.cpeMatch.forEach((match: any) => {
              if (match?.criteria) {
                const cpe = match.criteria;
                const parts = cpe.split(':');
                if (parts.length >= 5) {
                  products.add(`${parts[4]}:${parts[5]}`);
                }
              }
            });
          }
        });
      }
    });

    return Array.from(products).slice(0, 10);
  }

  private checkIfExploited(cveId: string): boolean {
    // This would be integrated with CISA KEV data
    // For now, returning false - to be enhanced
    return false;
  }

  getCache(): NodeCache {
    return this.cache;
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('NVD cache cleared');
  }
}
