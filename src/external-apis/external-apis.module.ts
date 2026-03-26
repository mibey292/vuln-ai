import { Module } from '@nestjs/common';
import { NvdApiService } from './nvd-api.service';
import { GitHubSecurityApiService } from './github-security.service';
import { CisaApiService } from './cisa-api.service';
import { BreachCheckService } from './breach-check.service';
import { EmailValidationService } from './email-validation.service';
import { WebsiteAnalysisService } from './website-analysis.service';

@Module({
  providers: [
    NvdApiService,
    GitHubSecurityApiService,
    CisaApiService,
    BreachCheckService,
    EmailValidationService,
    WebsiteAnalysisService,
  ],
  exports: [
    NvdApiService,
    GitHubSecurityApiService,
    CisaApiService,
    BreachCheckService,
    EmailValidationService,
    WebsiteAnalysisService,
  ],
})
export class ExternalApisModule {}
