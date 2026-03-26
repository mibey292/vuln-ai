import { Module } from '@nestjs/common';
import { NvdApiService } from './nvd-api.service';
import { GitHubSecurityApiService } from './github-security.service';
import { CisaApiService } from './cisa-api.service';

@Module({
  providers: [NvdApiService, GitHubSecurityApiService, CisaApiService],
  exports: [NvdApiService, GitHubSecurityApiService, CisaApiService],
})
export class ExternalApisModule {}
