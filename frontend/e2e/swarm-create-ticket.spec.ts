import { expect, test } from './fixtures';

test('swarm detail can hand off ticket draft to remediation route', async ({ page }) => {
  const swarmJob = {
    id: 'job-e2e-1',
    name: 'Suspicious Identity Investigation — user@company.com',
    profile: 'INCIDENT_RESPONSE',
    status: 'completed',
    requested_by: 'e2e-user',
    trigger_type: 'manual',
    input_json: '{}',
    classification: 'confidential',
    participants_json: JSON.stringify(['identityclaw', 'threatclaw', 'cloudclaw']),
    parallelism: 3,
    overall_severity: 'high',
    confidence: 0.91,
    final_summary: 'Done',
    result_json: JSON.stringify({
      executive_summary: 'High-risk identity activity detected.',
      root_cause: 'Suspicious privilege escalation pattern.',
      blast_radius: 'Identity + cloud control plane.',
      next_steps: ['Open ticket', 'Notify owner'],
      top_findings: [{ title: 'Global admin assignment outside policy window' }],
      recommended_actions: ['Review admin grants'],
      compliance_impact: ['SOC2-CC6', 'CIS-2.1'],
      judge_model: { provider: 'nvidia_nim', profile: 'swarm_judge_profile', model: 'meta/llama' },
    }),
    error_message: null,
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  };

  const tasks = [
    {
      id: 'task-1',
      swarm_job_id: 'job-e2e-1',
      claw: 'complianceclaw',
      task_type: 'investigate',
      status: 'completed',
      model_profile: null,
      severity: 'high',
      confidence: 0.88,
      risk_score: 72,
      input_json: '{}',
      output_json: JSON.stringify({ compliance_mappings: ['SOC2-CC6', 'ISO27001-A.5'] }),
      execution_time_ms: 350,
      error_message: null,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    },
  ];

  await page.route('**/api/v1/swarm/jobs/job-e2e-1', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(swarmJob) });
  });
  await page.route('**/api/v1/swarm/jobs/job-e2e-1/tasks', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(tasks) });
  });
  await page.route('**/api/v1/swarm/jobs/job-e2e-1/stream**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
  });

  let remediationCallSeen = false;
  await page.route('**/api/v1/remediation/trigger', async (route) => {
    remediationCallSeen = true;
    const req = route.request();
    const payload = req.postDataJSON() as any;
    expect(payload.action_spec.provider).toBe('jira');
    expect(payload.action_spec.target_type).toBe('ticket');
    expect(payload.action_spec.action_type).toBe('create_jira_ticket');
    expect(payload.action_spec.parameters.project_key).toBe('SEC');
    expect(payload.action_spec.parameters.description).toContain('Executive Summary:');
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        triggered: 1,
        actions: [{ id: 'action-123', action_type: 'create_jira_ticket' }],
      }),
    });
  });

  await page.goto('/swarm/job-e2e-1');

  await expect(page.getByText('Ticket Draft')).toBeVisible();
  await page.getByRole('button', { name: 'Create Ticket' }).click();
  await expect(page.getByText('Ticket action queued: action-123')).toBeVisible();
  expect(remediationCallSeen).toBeTruthy();
});
