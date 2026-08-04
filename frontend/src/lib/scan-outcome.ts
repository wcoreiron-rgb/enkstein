export type ScanOutcome = {
  mode?: string;
  data_source?: string;
  evidence_status?: string;
  findings_created?: number;
  findings_updated?: number;
  critical?: number;
  high?: number;
  message?: string;
};

/** Render an evidence-first outcome for every Capability Node scan. */
export function describeScanOutcome(result: ScanOutcome): { type: 'success' | 'error'; text: string } {
  const source = result.data_source ?? (result.mode === 'live' ? 'live_connector' : 'no_data_source');
  if (source === 'no_data_source' || result.mode === 'empty') {
    return {
      type: 'error',
      text: result.message ?? 'No verified environment evidence was available. Connect and test a provider before scanning.',
    };
  }
  if (source === 'seeded_fallback' || result.mode === 'simulated') {
    return {
      type: 'error',
      text: result.message ?? 'Demo evidence only. It is not an assessment of this environment.',
    };
  }
  const counts = `${result.findings_created ?? 0} new, ${result.findings_updated ?? 0} updated`;
  const severity = result.critical !== undefined || result.high !== undefined
    ? ` Critical: ${result.critical ?? 0}, High: ${result.high ?? 0}.`
    : '.';
  return { type: 'success', text: `Live evidence scan complete — ${counts}.${severity}` };
}
