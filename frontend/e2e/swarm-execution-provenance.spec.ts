import { expect, test } from '@playwright/test';

test('swarm detail shows task execution provenance badges', async ({ page }) => {
  const swarmJob = {
    id: 'job-e2e-provenance',
    name: 'Execution Provenance Swarm',
    profile: 'INCIDENT_RESPONSE',
    status: 'completed',
    requested_by: 'e2e-user',
    trigger_type: 'manual',
    input_json: '{}',
    classification: 'internal',
    participants_json: JSON.stringify(['identityclaw', 'unknownclaw']),
    parallelism: 2,
    overall_severity: 'medium',
    confidence: 0.82,
    final_summary: 'Done',
    result_json: JSON.stringify({
      executive_summary: 'Mixed execution paths observed.',
      judge_model: { provider: 'nvidia_nim', profile: 'swarm_judge_profile', model: 'meta/llama' },
    }),
    error_message: null,
    created_at: new Date().toISOString(),
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
  };

  const tasks = [
    {
      id: 'task-real',
      swarm_job_id: 'job-e2e-provenance',
      claw: 'identityclaw',
      task_type: 'investigate',
      status: 'completed',
      model_profile: null,
      severity: 'high',
      confidence: 0.88,
      risk_score: 71,
      input_json: '{}',
      output_json: JSON.stringify({
        execution_mode: 'real_task_handler',
        findings: [{ title: 'real', detail: 'real handler path' }],
      }),
      execution_time_ms: 230,
      error_message: null,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    },
    {
      id: 'task-fallback',
      swarm_job_id: 'job-e2e-provenance',
      claw: 'unknownclaw',
      task_type: 'investigate',
      status: 'completed',
      model_profile: null,
      severity: 'medium',
      confidence: 0.7,
      risk_score: 41,
      input_json: '{}',
      output_json: JSON.stringify({
        execution_mode: 'simulated_fallback',
        fallback_reason: "Unsupported claw 'unknownclaw' does not provide /task handler",
        findings: [{ title: 'simulated', detail: 'fallback path' }],
      }),
      execution_time_ms: 410,
      error_message: null,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    },
  ];

  await page.route('**/api/v1/swarm/jobs/job-e2e-provenance', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(swarmJob) });
  });
  await page.route('**/api/v1/swarm/jobs/job-e2e-provenance/tasks', async (route) => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(tasks) });
  });
  await page.route('**/api/v1/swarm/jobs/job-e2e-provenance/stream**', async (route) => {
    await route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
  });

  await page.goto('/swarm/job-e2e-provenance');

  await expect(page.getByRole('heading', { name: 'Tasks' })).toBeVisible();
  await expect(page.getByText('real handler')).toBeVisible();
  await expect(page.getByText('simulated fallback')).toBeVisible();
  await expect(page.getByText("Unsupported claw 'unknownclaw' does not provide /task handler")).toBeVisible();
});
