import { expect, test } from '@playwright/test';

import { capabilityName, marcellusText } from '../src/lib/capability-names';

test('capability names render known and future compatibility identifiers', () => {
  expect(capabilityName('IdentityClaw')).toBe('Identity Security');
  expect(capabilityName('identityclaw')).toBe('Identity Security');
  expect(capabilityName('future_claw')).toBe('Future');
});

test('display text preserves external products and compatibility paths', () => {
  expect(marcellusText('Dispatch to an external OpenClaw agent')).toContain('OpenClaw');
  expect(marcellusText('Call /api/v1/identityclaw/task')).toContain('/api/v1/identityclaw/task');
  expect(marcellusText('IdentityClaw and CloudClaw completed')).toBe(
    'Identity Security and Cloud Security completed',
  );
  expect(marcellusText('Three claws completed')).toBe('Three Capability Nodes completed');
});
