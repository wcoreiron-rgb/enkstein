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

export function capabilityName(value?: string | null): string {
  if (!value) return 'Unassigned Capability';
  const key = keyFor(value);
  const known = CAPABILITY_NAMES[key];
  if (known) return known;

  const withoutSuffix = value.replace(/claw$/i, '').replace(/[_-]+/g, ' ').trim();
  if (!withoutSuffix) return 'Capability Node';
  return withoutSuffix.replace(/\b\w/g, character => character.toUpperCase());
}

export function marcellusText(value?: string | null): string {
  if (!value) return '';
  let result = value.replace(/RegentClaw/g, 'Marcellus');
  for (const [key, displayName] of Object.entries(CAPABILITY_NAMES)) {
    const legacyName = `${key.slice(0, -4)}Claw`;
    result = result.replace(new RegExp(legacyName, 'gi'), displayName);
  }
  return result;
}

export { CAPABILITY_NAMES };
