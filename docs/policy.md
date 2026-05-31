# Policy Model

Policies decide whether a tool call is allowed, denied, or requires proof.

```ts
export const policy = {
  version: 'permitrail.policy.v1',
  id: 'production-policy',
  defaults: {
    unconfiguredTool: 'deny',
  },
  tools: {
    'email.send': {
      id: 'email-send-human-approval',
      risk: 'medium',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 300,
        bindActionInputHash: true,
      },
    },
    'calendar.read': {
      id: 'calendar-read-low-risk',
      mode: 'allow',
    },
  },
};
```

## Decision Outcomes

| Outcome | Meaning |
| --- | --- |
| `allow` | The tool call can run |
| `deny` | The tool call must not run |
| `require_proof` | The tool call needs a proof challenge |

## Recommended Defaults

- Unknown tools should be denied.
- Mutating tools should require proof.
- External communication should require proof.
- Payments should require proof bound to exact amount and recipient.
- Delete operations should require admin-level proof.
- Proof TTL should be short: 2 to 5 minutes for risky actions.

## Risk-Based Policy

Suggested baseline:

| Risk | Examples | Default |
| --- | --- | --- |
| Low | read-only calendar, read own profile | allow or account proof |
| Medium | send email, update CRM, create ticket | human approval |
| High | payment, delete data, merge PR, sign document | human approval plus strict input hash |
| Critical | production database mutation, legal signature, high spend | admin approval plus second factor |
