import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';

export interface BreachInfo {
  name: string;
  breachDate: string;
  addedDate: string;
  description: string;
  count: number;
}

@Injectable()
export class BreachCheckService {
  private readonly logger = new Logger(BreachCheckService.name);
  private readonly apiClient: AxiosInstance;
  private readonly cache: NodeCache;
  private readonly HIBP_URL = 'https://haveibeenpwned.com/api/v3';
  private readonly CACHE_TTL = 86400; // 24 hours

  constructor() {
    this.apiClient = axios.create({
      baseURL: this.HIBP_URL,
      timeout: 10000,
      headers: {
        'User-Agent': 'VulnAI-SecurityChat',
      },
    });
    this.cache = new NodeCache({ stdTTL: this.CACHE_TTL });
  }

  async checkEmail(email: string): Promise<BreachInfo[]> {
    const cacheKey = `breach:${email}`;
    const cached = this.cache.get<BreachInfo[]>(cacheKey);
    if (cached !== undefined) {
      this.logger.debug(`Cache hit for email breach check: ${email}`);
      return cached;
    }

    try {
      this.logger.log(`Checking breach database for: ${email}`);
      const response = await this.apiClient.get(`/breachedaccount/${encodeURIComponent(email)}`);

      const breaches: BreachInfo[] = (response.data || []).map((breach: any) => ({
        name: breach.Name,
        breachDate: breach.BreachDate,
        addedDate: breach.AddedDate,
        description: breach.Description,
        count: breach.PwnCount,
      }));

      this.cache.set(cacheKey, breaches);
      return breaches;
    } catch (error: any) {
      if (error.response?.status === 404) {
        this.logger.log(`No breaches found for: ${email}`);
        this.cache.set(cacheKey, []);
        return [];
      }
      this.logger.error(`Error checking breaches for ${email}: ${error}`);
      return [];
    }
  }

  async checkUsername(username: string): Promise<BreachInfo[]> {
    const cacheKey = `breach:user:${username}`;
    const cached = this.cache.get<BreachInfo[]>(cacheKey);
    if (cached !== undefined) {
      this.logger.debug(`Cache hit for username breach check: ${username}`);
      return cached;
    }

    try {
      this.logger.log(`Checking breach database for username: ${username}`);
      const response = await this.apiClient.get(`/breachedaccount/${encodeURIComponent(username)}`);

      const breaches: BreachInfo[] = (response.data || []).map((breach: any) => ({
        name: breach.Name,
        breachDate: breach.BreachDate,
        addedDate: breach.AddedDate,
        description: breach.Description,
        count: breach.PwnCount,
      }));

      this.cache.set(cacheKey, breaches);
      return breaches;
    } catch (error: any) {
      if (error.response?.status === 404) {
        this.logger.log(`No breaches found for username: ${username}`);
        this.cache.set(cacheKey, []);
        return [];
      }
      this.logger.error(`Error checking breaches for username ${username}: ${error}`);
      return [];
    }
  }

  clearCache(): void {
    this.logger.log('Clearing breach check cache');
    this.cache.flushAll();
  }
}
