# Optional attachment metadata

Exchange message-tracking logs do not include attachment names. Exchange Guard therefore displays `Not collected` until a separate authorized source submits metadata.

The application never needs or accepts message bodies or attachment content. Submit only filename, MIME type and size.

## Suitable metadata sources

Possible sources include:

- an existing secure email gateway or DLP product that already records attachment metadata;
- a journaling/archiving integration authorized by your organization;
- a custom Exchange transport agent developed and reviewed for this purpose;
- a narrowly scoped mailbox investigation workflow used only during an incident.

This repository does not include a mailbox-content crawler. Deploying broad EWS impersonation solely to populate a dashboard would create more risk than the feature is worth.

## JSON format

Prepare a local JSON file:

```json
{
  "items": [
    {
      "sender": "user@example.com",
      "message_id": "<example-message-id@example.com>",
      "network_message_id": "",
      "event_key": "",
      "attachments": [
        {
          "filename": "report.pdf",
          "content_type": "application/pdf",
          "size_bytes": 245760
        }
      ]
    }
  ]
}
```

At least one matching identifier is required:

- `message_id` is usually the easiest choice and must match the tracking event.
- `network_message_id` may be used when available.
- `event_key` is the internal evidence hash and is useful only when another integration has already obtained it.

An empty `attachments` array records a known **none** state. Omitting a message entirely leaves it as **Not collected**.

Limits:

- at most 1,000 message items per request;
- at most 50 filenames per message;
- filename is reduced to its final path component and capped by the server;
- no binary data, body, hash or attachment content is accepted by this endpoint.

## Signed submission

Use the included helper from a trusted Windows host:

```powershell
Set-Location 'C:\Temp\exchange-guard-control\integrations\exchange'

.\Submit-ExchangeGuardAttachmentMetadata.ps1 `
    -BaseUrl 'https://exchange-guard.example.internal' `
    -NodeId 'mailbox-01' `
    -JsonPath 'C:\Temp\attachment-metadata.json'
```

The script securely prompts for `MAILBOX_NODE_SECRET`, reconstructs a strict metadata-only payload and signs it with the same HMAC scheme used by the mailbox agent.

A successful response reports:

- number of items received;
- number of outbound evidence rows matched;
- number of filenames processed.

If `matched_evidence` is zero, compare the normalized sender and message/network ID with the corresponding row in `GetMessageTrackingLog`, then run an outbound scan so evidence exists before resubmitting metadata.

## Privacy and retention

Filenames can contain personal or sensitive information. Treat attachment metadata like message subjects:

- collect only when justified;
- restrict administrator access;
- align retention with your policy;
- do not export it into public diagnostics;
- delete local JSON staging files securely after the authorized workflow is complete.

