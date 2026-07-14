const capabilityRewrites = [
  ['ai-security', 'arcclaw'],
  ['cloud-security', 'cloudclaw'],
  ['identity-security', 'identityclaw'],
  ['privileged-access', 'accessclaw'],
  ['endpoint-security', 'endpointclaw'],
  ['network-security', 'netclaw'],
  ['data-security', 'dataclaw'],
  ['application-security', 'appclaw'],
  ['saas-security', 'saasclaw'],
  ['threat-analysis', 'threatclaw'],
  ['security-telemetry', 'logclaw'],
  ['threat-intelligence', 'intelclaw'],
  ['user-risk', 'userclaw'],
  ['insider-risk', 'insiderclaw'],
  ['security-automation', 'automationclaw'],
  ['attack-path-analysis', 'attackpathclaw'],
  ['exposure-management', 'exposureclaw'],
  ['compliance-assurance', 'complianceclaw'],
  ['privacy-governance', 'privacyclaw'],
  ['vendor-risk', 'vendorclaw'],
  ['terraform-governance', 'terraclaw'],
  ['developer-security', 'devclaw'],
  ['configuration-security', 'configclaw'],
  ['release-governance', 'releaseclaw'],
  ['recovery-readiness', 'recoveryclaw'],
  ['custom', 'customclaw'],
].map(([slug, legacyRoute]) => ({
  source: `/capabilities/${slug}`,
  destination: `/${legacyRoute}`,
}));

/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    // INTERNAL_API_URL is server-side only (no NEXT_PUBLIC_ prefix).
    // It resolves to http://backend:8000 inside Docker, or http://localhost:8000
    // when running locally outside Docker.
    // The browser never sees this URL — it only ever calls /api/v1/... which
    // Next.js intercepts here and proxies to the backend.
    const target = process.env.INTERNAL_API_URL || 'http://localhost:8000';
    return [
      ...capabilityRewrites,
      {
        source: '/model-cortex',
        destination: '/modelclaw',
      },
      {
        source: '/api/:path*',
        destination: `${target}/api/:path*`,
      },
      {
        source: '/runtime-info',
        destination: `${target}/health`,
      },
    ];
  },
};

module.exports = nextConfig;
