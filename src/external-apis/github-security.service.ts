import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { CVEDto } from '../vulnerability/dto/cve.dto';

@Injectable()
export class GitHubSecurityApiService {
  private readonly logger = new Logger(GitHubSecurityApiService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly GITHUB_API_URL = 'https://api.github.com/graphql';
  private readonly CACHE_TTL = 3600;

  constructor() {
    const githubToken = process.env.GITHUB_TOKEN;
    this.apiClient = axios.create({
      baseURL: 'https://api.github.com',
      timeout: 10000,
      headers: {
        Authorization: `Bearer ${githubToken}`,
        'Content-Type': 'application/json',
      },
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  async searchAdvisories(query: string, limit: number = 5): Promise<CVEDto[]> {
    const cacheKey = `github:search:${query}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for GitHub search: ${query}`);
      return cached;
    }

    try {
      this.logger.log(`Searching GitHub Security Advisories for: ${query}`);
      const response = await this.apiClient.get('/advisory-database/advisories', {
        params: {
          type: 'reviewed',
          keyword: query,
          limit,
        },
      });

      const advisories = (response.data?.advisories || [])
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error searching GitHub advisories: ${error}`);
      return [];
    }
  }

  async getAdvisoriesByPackage(
    packageName: string,
    ecosystem: 'npm' | 'pip' | 'maven' | 'cargo' = 'npm',
    limit: number = 5,
  ): Promise<CVEDto[]> {
    const cacheKey = `github:${ecosystem}:${packageName}`;
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for GitHub package: ${packageName}`);
      return cached;
    }

    try {
      this.logger.log(`Fetching GitHub advisories for ${ecosystem} package: ${packageName}`);
      const response = await this.apiClient.get('/advisory-database/advisories', {
        params: {
          type: 'reviewed',
          ecosystem,
          package_name: packageName,
          sort: 'updated',
          per_page: limit,
        },
      });

      const advisories = (response.data?.advisories || [])
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error fetching GitHub advisories for ${packageName}: ${error}`);
      return [];
    }
  }

  async getRecentAdvisories(limit: number = 20): Promise<CVEDto[]> {
    const cacheKey = 'github:recent';
    const cached = this.cache.get<CVEDto[]>(cacheKey);
    if (cached) {
      this.logger.debug('Cache hit for recent GitHub advisories');
      return cached;
    }

    try {
      this.logger.log('Fetching recent GitHub advisories');
      const response = await this.apiClient.get('/advisory-database/advisories', {
        params: {
          type: 'reviewed',
          sort: 'published',
          direction: 'desc',
          per_page: limit,
        },
      });

      const advisories = (response.data?.advisories || [])
        .map((adv: any) => this.parseGitHubAdvisory(adv))
        .slice(0, limit);

      this.cache.set(cacheKey, advisories);
      return advisories;
    } catch (error) {
      this.logger.warn(`Error fetching recent GitHub advisories: ${error}`);
      return [];
    }
  }

  private parseGitHubAdvisory(advisory: any): CVEDto {
    return {
      id: advisory.cve_id || advisory.ghsa_id || 'UNKNOWN',
      publishedDate: advisory.published_at || advisory.created_at,
      published: new Date(advisory.published_at || advisory.created_at).getFullYear(),
      description: advisory.description || advisory.summary || 'No description available',
      metrics: {
        cvssV31Score: advisory.cvss?.score,
        cvssV31Severity: advisory.cvss?.vector_string || advisory.severity,
      },
      affectedProducts: advisory.affected?.map((a: any) => `${a.package?.name}:${a.ranges?.[0]?.introduced || 'all'}`),
      references: [
        {
          url: advisory.github_reviewed_at ? `https://github.com/advisories/${advisory.ghsa_id}` : advisory.references?.[0] || '',
          source: 'GitHub Security Advisory',
          tags: ['github-advisory', advisory.severity?.toLowerCase()],
        },
      ],
      githubAdvisoryUrl: `https://github.com/advisories/${advisory.ghsa_id}`,
      isExploited: advisory.references?.some((ref: string) => ref.includes('exploit')) || false,
    };
  }

  clearCache(): void {
    this.cache.flushAll();
    this.logger.log('GitHub Security API cache cleared');
  }
}
