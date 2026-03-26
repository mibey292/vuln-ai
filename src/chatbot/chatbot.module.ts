import { Module } from '@nestjs/common';
import { ChatbotController } from './chatbot.controller';
import { ChatbotService } from './chatbot.service';
import { VulnerabilityModule } from '../vulnerability/vulnerability.module';
import { AnalyticsModule } from '../analytics/analytics.module';
import { LlmModule } from '../llm/llm.module';
import { ExternalApisModule } from '../external-apis/external-apis.module';

@Module({
  imports: [VulnerabilityModule, AnalyticsModule, LlmModule, ExternalApisModule],
  controllers: [ChatbotController],
  providers: [ChatbotService],
  exports: [ChatbotService],
})
export class ChatbotModule {}
