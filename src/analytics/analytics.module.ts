import { Module } from '@nestjs/common';
import { ThreatAnalyzerService } from './threat-analyzer.service';
import { RiskCalculatorService } from './risk-calculator.service';

@Module({
  providers: [ThreatAnalyzerService, RiskCalculatorService],
  exports: [ThreatAnalyzerService, RiskCalculatorService],
})
export class AnalyticsModule {}
