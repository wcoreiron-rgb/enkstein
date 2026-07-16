const CAPABILITY_NAMES: Record<string, string> = {
  accessclaw: 'Privileged Access',
  appclaw: 'Application Security',
  arcclaw: 'AI Security',
  attackpathclaw: 'Attack Path Analysis',
  automationclaw: 'Security Automation',
  cloudclaw: 'Cloud Security',
  complianceclaw: 'Compliance Assurance',
  configclaw: 'Configuration Security',
  customclaw: 'Custom Capability',
  dataclaw: 'Data Security',
  devclaw: 'Developer Security',
  endpointclaw: 'Endpoint Security',
  exposureclaw: 'Exposure Management',
  identityclaw: 'Identity Security',
  insiderclaw: 'Insider Risk',
  intelclaw: 'Threat Intelligence',
  logclaw: 'Security Telemetry',
  memoryclaw: 'Memory Cortex',
  modelclaw: 'Model Cortex',
  netclaw: 'Network Security',
  privacyclaw: 'Privacy Governance',
  recoveryclaw: 'Recovery Readiness',
  releaseclaw: 'Release Governance',
  saasclaw: 'SaaS Security',
  terraclaw: 'Terraform Governance',
  threatclaw: 'Threat Analysis',
  userclaw: 'User Risk',
  vendorclaw: 'Vendor Risk',
};

function keyFor(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function titleCase(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // split camelCase
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
}

/**
 * Resolve any capability identifier (persisted `claw` values, API path
 * segments, PascalCase legacy names, unknown future `somethingclaw` ids)
 * to its Enkstein presentation name.
 */
export function capabilityName(value?: string | null): string {
  if (!value) return 'Unassigned Capability';
  const key = keyFor(value);
  const known = CAPABILITY_NAMES[key];
  if (known) return known;

  const withoutSuffix = value.replace(/[_-]?claw$/i, '');
  if (!keyFor(withoutSuffix)) return 'Capability Node';
  return titleCase(withoutSuffix);
}

// Phrase-level replacements applied before token replacement so the official
// Enkstein vocabulary wins over the generic fallback.
const PHRASE_REPLACEMENTS: Array<[RegExp, string]> = [
  [/\bRegentClaw\b/gi, 'Enkstein'],
  [/\bparticipating claws\b/gi, 'participating Capability Nodes'],
  [/\brun a claw\b/gi, 'run a Capability'],
  [/\bclaw output\b/gi, 'Capability output'],
  [/\bclaw task(s?)\b/gi, 'Capability task$1'],
];

/**
 * Sanitize backend-provided display text (descriptions, policy text,
 * findings, events, timelines, API-generated messages) by replacing legacy
 * `XxxClaw` names with Enkstein presentation names. API paths (`/identityclaw`)
 * and snake_case identifiers (`source_claw`) are left untouched.
 */
export function marcellusText(value?: string | null): string {
  if (!value) return '';
  let result = value;
  for (const [pattern, replacement] of PHRASE_REPLACEMENTS) {
    result = result.replace(pattern, replacement);
  }
  // Replace only known legacy module names. This deliberately preserves
  // external product names such as OpenClaw and future unknown identifiers.
  for (const [legacyId, displayName] of Object.entries(CAPABILITY_NAMES)) {
    result = result.replace(new RegExp(`(?<!/)\\b${legacyId}\\b`, 'gi'), displayName);
  }
  // A former Claw is one Capability Node. Security Arms are broader pillars.
  result = result.replace(/(?<!\/)\bclaws\b/gi, 'Capability Nodes');
  result = result.replace(/(?<!\/)\bclaw\b/gi, 'Capability Node');
  return result;
}

export { CAPABILITY_NAMES };
