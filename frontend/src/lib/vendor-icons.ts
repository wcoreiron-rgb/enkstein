/**
 * Vendor marks bundled from simple-icons (CC0) at build time.
 *
 * These were previously fetched from cdn.simpleicons.org on every render,
 * which told a third party which connectors an operator was looking at and
 * left the page dependent on outbound internet. Eleven of the slugs in use
 * no longer exist upstream and returned 404 forever; those fall through to
 * the initials badge instead.
 */
export const BUNDLED_VENDOR_ICONS = new Set<string>([
  'anthropic',
  'cisco',
  'cloudflare',
  'datadog',
  'github',
  'gitlab',
  'googlegemini',
  'jira',
  'nvidia',
  'okta',
  'ollama',
  'pagerduty',
  'paloaltonetworks',
  'qualys',
  'vault',
  'virustotal',
  'vmware',
]);
