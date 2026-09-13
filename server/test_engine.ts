import { runMultiSignalEngine } from './src/engine';

async function test() {
  // Test STATIC analysis (DEMO mode)
  const result1 = await runMultiSignalEngine('https://chase-security-login-portal.xyz/auth/verify', 'DEMO', []);
  console.log('=== STATIC ANALYSIS (DEMO mode) ===');
  console.log('Risk Score:', result1.risk.score);
  console.log('Risk Level:', result1.risk.level);
  console.log('DNS Score:', result1.signals.dns);
  console.log('SSL Score:', result1.signals.ssl);
  console.log('Redirect Score:', result1.signals.redirects);
  console.log('DNS Status:', result1.signalDetails[5].status);
  console.log('SSL Status:', result1.signalDetails[6].status);
  console.log('Redirect Status:', result1.signalDetails[7].status);
  console.log('Engine:', result1.engineUsed);
  console.log('Mode:', result1.analysisMeta.mode);
  console.log('Live Probes:', JSON.stringify(result1.analysisMeta.liveProbesPerformed));
  console.log('Signals Computed:', result1.analysisMeta.signalsComputed);
  console.log();

  // Test LIVE analysis
  const result2 = await runMultiSignalEngine('https://github.com', 'LIVE', []);
  console.log('=== LIVE ANALYSIS ===');
  console.log('Risk Score:', result2.risk.score);
  console.log('Risk Level:', result2.risk.level);
  console.log('DNS Score:', result2.signals.dns);
  console.log('SSL Score:', result2.signals.ssl);
  console.log('Redirect Score:', result2.signals.redirects);
  console.log('DNS Status:', result2.signalDetails[5].status);
  console.log('SSL Status:', result2.signalDetails[6].status);
  console.log('Redirect Status:', result2.signalDetails[7].status);
  console.log('Engine:', result2.engineUsed);
  console.log('Mode:', result2.analysisMeta.mode);
  console.log('Live Probes:', JSON.stringify(result2.analysisMeta.liveProbesPerformed));
  console.log('Signals Computed:', result2.analysisMeta.signalsComputed);
  console.log();

  // Test safe site STATIC
  const result3 = await runMultiSignalEngine('https://microsoft.com', 'DEMO', []);
  console.log('=== SAFE SITE STATIC ANALYSIS ===');
  console.log('Risk Score:', result3.risk.score);
  console.log('Risk Level:', result3.risk.level);
  console.log('Matched Brand:', result3.matchedBrand);
  console.log('Engine:', result3.engineUsed);
  console.log('Mode:', result3.analysisMeta.mode);
  console.log('Live Probes:', JSON.stringify(result3.analysisMeta.liveProbesPerformed));
  console.log('Signals Computed:', result3.analysisMeta.signalsComputed);
}

test().catch(console.error);