# @permitrail/provider-webhook

Webhook approval provider for PermitRail.

This package routes each approval request to an HTTP endpoint, treats that
endpoint as the approver trust boundary, and signs a PermitRail proof only when
the endpoint explicitly returns `approved: true`.

## Install

```bash
npm install @permitrail/provider-webhook
```

## Use

```ts
import { WebhookApprovalProvider } from '@permitrail/provider-webhook';

const provider = await WebhookApprovalProvider.create({
  endpoint: 'https://approvals.example.com/permitrail',
  headers: { authorization: `Bearer ${process.env.APPROVAL_TOKEN}` },
  timeoutMs: 10_000,
});
```

The default transport requires HTTPS, except for localhost development. You can
inject a custom transport to add request signing, queues, private networking, or
tests without a network call.

## Links

- Repository: https://github.com/chokonaira/permitrail
- Threat model: https://github.com/chokonaira/permitrail/blob/main/docs/threat-model.md
- Policy model: https://github.com/chokonaira/permitrail/blob/main/docs/policy.md

## License

Apache-2.0
