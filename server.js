/**
 * IES / QuickBooks Training webhook relay.
 *
 * Quickbase Pipelines can't sign requests or set custom headers, so this
 * sits in between: Quickbase POSTs plain event data (with a shared secret
 * IN THE BODY, since Pipelines can't set headers) here. This service:
 *   1. validates the shared secret
 *   2. builds + signs the envelope per Jason Ruvaldt's contract (v1, 2026-09-17)
 *   3. sends it to the partner endpoint
 *   4. on 5xx/network failure, queues it and retries on the partner's own
 *      backoff schedule (1s, 5s, 30s, 5min, 30min, 6h; 24h total window)
 *   5. on 4xx, fails immediately — no retry, payload needs fixing
 *
 * On success — whether on the first attempt or after a background retry —
 * this service writes a success timestamp back into Quickbase itself,
 * using table_id/key_field_id/key_value/field_id supplied in the ORIGINAL Quickbase
 * payload. This closes the loop for the delayed-retry case, where the
 * Pipeline run that triggered the event has long since finished by the
 * time the partner actually accepts it.
 *
 * Env vars (set in Railway):
 *   INTUIT_INTERNAL_SECRET   - the prod HMAC secret Jason gave you
 *   INBOUND_SHARED_SECRET    - a secret YOU pick; Quickbase must include it
 *                              as "webhook_secret" in the JSON body
 *   QB_USER_TOKEN            - Quickbase user token, same pattern as your
 *                              other Railway projects, used to write the
 *                              success timestamp back to the record
 *   QB_REALM_HOSTNAME        - e.g. "intuit.quickbase.com" — required by
 *                              Quickbase's REST API alongside the user token
 *   RETRY_QUEUE_PATH         - optional, defaults to ./retry-queue.json.
 *                              Point this at a mounted Railway Volume path
 *                              (e.g. /data/retry-queue.json) so queued
 *                              retries survive a redeploy/restart. Without
 *                              a volume, Railway's ephemeral filesystem
 *                              means an in-flight retry queue is LOST on
 *                              restart.
 *   PORT                     - Railway sets this automatically
 */

import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';

const app = express();
app.use(express.json());

const INTUIT_INTERNAL_SECRET = process.env.INTUIT_INTERNAL_SECRET;
const INBOUND_SHARED_SECRET = process.env.INBOUND_SHARED_SECRET;
const QB_USER_TOKEN = process.env.QB_USER_TOKEN;
const QB_REALM_HOSTNAME = process.env.QB_REALM_HOSTNAME;
const RETRY_QUEUE_PATH = process.env.RETRY_QUEUE_PATH || './retry-queue.json';

if (!INTUIT_INTERNAL_SECRET) throw new Error('Missing INTUIT_INTERNAL_SECRET env var');
if (!INBOUND_SHARED_SECRET) throw new Error('Missing INBOUND_SHARED_SECRET env var');
if (!QB_USER_TOKEN) throw new Error('Missing QB_USER_TOKEN env var');
if (!QB_REALM_HOSTNAME) throw new Error('Missing QB_REALM_HOSTNAME env var');

// NOTE: we deliberately do NOT hardcode field 3 (Record ID#) as the match
// field anymore. Quickbase's upsert endpoint rejects field 3 outright when
// a table's configured key field is something else (e.g. a custom Email
// Address key field) — "You cannot include the record ID if it is not the
// key field." Instead, every write-back call passes its own mergeFieldId
// (via key_field_id/key_value in the original Pipeline payload), so
// this works for both record-id-keyed tables and custom-key tables like
// the Users table (bwdgu5vwg, keyed on Email Address, field 6).

const PARTNER_HOST = 'intuitenterprisesuitetraining.com';
const PARTNER_PATH = '/api/partners/intuit/events';
const PARTNER_URL = `https://${PARTNER_HOST}${PARTNER_PATH}`;

// Per the contract's retry policy. Values in ms.
const BACKOFF_SCHEDULE_MS = [1_000, 5_000, 30_000, 5 * 60_000, 30 * 60_000, 6 * 60 * 60_000];
const MAX_RETRY_WINDOW_MS = 24 * 60 * 60_000;
const QUEUE_POLL_INTERVAL_MS = 5_000;

const VALID_EVENT_TYPES = new Set([
  'ping', '', 'user.updated', 'user.deactivated', 'user.reactivated',
  'user.deleted', 'org.created', 'org.updated', 'org.deactivated', 'org.reactivated',
  'user.added_to_org', 'user.removed_from_org', 'welcome_email.resend',
]);

const REQUIRED_FIELDS = {
  'ping': [],
  'user.created': ['intuit_user_id', 'email', 'first_name', 'last_name'],
  'user.updated': ['intuit_user_id'],
  'user.deactivated': ['intuit_user_id'],
  'user.reactivated': ['intuit_user_id'],
  'user.deleted': ['intuit_user_id'],
  'org.created': ['intuit_org_id', 'name'], // leader_intuit_user_id is optional as of 2026-09-22
  'org.updated': ['intuit_org_id', 'name'],
  'org.deactivated': ['intuit_org_id'],
  'org.reactivated': ['intuit_org_id'],
  'user.added_to_org': ['intuit_user_id', 'intuit_org_id'],
  'user.removed_from_org': ['intuit_user_id', 'intuit_org_id'],
  'welcome_email.resend': ['intuit_user_id'],
};

// Write-back metadata: which Quickbase record to stamp on success, and
// which field to stamp with the success date/time. Required on every
// real event — EXCEPT `ping` (no record backs a connectivity test) and
// `user.deleted` (the triggering record is gone by the time this fires,
// so there's nothing left to stamp).
//   table_id        - the table to write to
//   key_field_id  - which field identifies the record to update (e.g.
//                      3 for Record ID# on most tables, 6 for Email
//                      Address on the Users table)
//   key_value     - the value to match on that field (a record ID
//                      number, or an email address string)
//   field_id        - the date/time field to stamp with the success time
const WRITE_BACK_FIELDS = ['table_id', 'key_field_id', 'key_value', 'field_id'];
const EVENTS_WITHOUT_WRITE_BACK = new Set(['ping', 'user.deleted']);

// ---------- Persistent retry queue (plain JSON file) ----------

function loadQueue() {
  try {
    const raw = fs.readFileSync(RETRY_QUEUE_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return []; // no file yet, or unreadable — start fresh
  }
}

function saveQueue(queue) {
  try {
    fs.writeFileSync(RETRY_QUEUE_PATH, JSON.stringify(queue, null, 2));
  } catch (err) {
    console.error('Failed to persist retry queue to disk:', err);
  }
}

let queue = loadQueue();
if (queue.length > 0) {
  console.log(`Loaded ${queue.length} pending retr${queue.length === 1 ? 'y' : 'ies'} from ${RETRY_QUEUE_PATH}`);
}

// ---------- Secret check (constant-time) ----------

function secretMatches(provided) {
  if (typeof provided !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(INBOUND_SHARED_SECRET);
  if (a.length !== b.length) return false; // timingSafeEqual requires equal length
  return crypto.timingSafeEqual(a, b);
}

// ---------- Signing ----------

function signBody(bodyString, secretHex) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const canonical = ['v1', 'POST', PARTNER_PATH, timestamp, bodyString].join('\n');
  const digest = crypto.createHmac('sha256', secretHex).update(canonical, 'utf8').digest('hex').toLowerCase();
  return { timestamp, signature: `sha256=${digest}` };
}

/**
 * One send attempt. bodyString is fixed for a given event_id (so the
 * partner's dedup works across retries) — timestamp/signature are
 * recomputed fresh every attempt, since the partner only accepts a
 * timestamp within a 5min-past/1min-future window.
 */
async function attemptSend(bodyString) {
  const { timestamp, signature } = signBody(bodyString, INTUIT_INTERNAL_SECRET);
  const response = await fetch(PARTNER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-intuit-signature': signature,
      'x-intuit-timestamp': timestamp,
    },
    body: bodyString,
  });
  const result = await response.json().catch(() => null);
  return { status: response.status, result };
}

// ---------- Quickbase write-back ----------

/**
 * Stamps the given field on the given record with the current date/time,
 * via Quickbase's REST API upsert endpoint. Called on success — whether
 * that success happened immediately or after a background retry.
 *
 * Never throws — a failed write-back is logged loudly but doesn't crash
 * the retry loop or the request handler. If this fails, the record will
 * look "unconfirmed" in Quickbase even though the partner accepted the
 * event; that's a real gap to watch for (check Railway logs / GET /queue
 * mismatches against Quickbase), but it shouldn't take down the relay.
 */
async function stampQuickbaseSuccess({ eventId, eventType, tableId, keyFieldId, keyValue, fieldId }) {
  const nowIso = new Date().toISOString();

  const body = {
    to: tableId,
    mergeFieldId: Number(keyFieldId), // explicit match field — see note above on why field 3 can't be assumed
    data: [
      {
        [String(keyFieldId)]: { value: keyValue },
        [String(fieldId)]: { value: nowIso },
      },
    ],
  };

  try {
    const response = await fetch('https://api.quickbase.com/v1/records', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'QB-Realm-Hostname': QB_REALM_HOSTNAME,
        Authorization: `QB-USER-TOKEN ${QB_USER_TOKEN}`,
      },
      body: JSON.stringify(body),
    });

    const result = await response.json().catch(() => null);

    if (!response.ok) {
      console.error(`[${eventId}] ${eventType} -> QUICKBASE WRITE-BACK FAILED (${response.status}) for table ${tableId} match field ${keyFieldId}=${keyValue} field ${fieldId}:`, result);
      return { ok: false, status: response.status, result };
    }

    console.log(`[${eventId}] ${eventType} -> stamped ${nowIso} on table ${tableId} (matched field ${keyFieldId}=${keyValue}) field ${fieldId}`);
    return { ok: true, status: response.status, result };
  } catch (err) {
    console.error(`[${eventId}] ${eventType} -> QUICKBASE WRITE-BACK FAILED (network) for table ${tableId} match field ${keyFieldId}=${keyValue} field ${fieldId}:`, err);
    return { ok: false, error: String(err) };
  }
}

// ---------- Queue processing ----------

function nextDelayMs(attemptCount) {
  const idx = Math.min(attemptCount, BACKOFF_SCHEDULE_MS.length - 1);
  return BACKOFF_SCHEDULE_MS[idx];
}

async function processQueueEntry(entry) {
  let sendResult;
  try {
    sendResult = await attemptSend(entry.bodyString);
  } catch (err) {
    // network-level failure — treat like a 5xx for retry purposes
    return handleFailure(entry, `network error: ${err}`);
  }

  const { status, result } = sendResult;

  if (status >= 200 && status < 300) {
    console.log(`[${entry.eventId}] ${entry.eventType} -> SUCCESS on retry (attempt ${entry.attemptCount + 1})`, result);
    if (!EVENTS_WITHOUT_WRITE_BACK.has(entry.eventType)) {
      await stampQuickbaseSuccess({
        eventId: entry.eventId,
        eventType: entry.eventType,
        tableId: entry.tableId,
        keyFieldId: entry.keyFieldId,
        keyValue: entry.keyValue,
        fieldId: entry.fieldId,
      });
    }
    return 'done';
  }

  if (status >= 400 && status < 500) {
    console.error(`[${entry.eventId}] ${entry.eventType} -> PERMANENT FAILURE (${status}), not retrying`, result);
    return 'done'; // remove from queue; needs manual fix, won't succeed on retry
  }

  // 5xx
  return handleFailure(entry, `partner returned ${status}: ${JSON.stringify(result)}`);
}

function handleFailure(entry, reasonText) {
  entry.attemptCount += 1;
  entry.lastError = reasonText;
  const elapsedSinceFirstFailure = Date.now() - entry.firstFailedAt;

  if (elapsedSinceFirstFailure >= MAX_RETRY_WINDOW_MS) {
    console.error(`[${entry.eventId}] ${entry.eventType} -> GIVING UP after 24h retry window. Last error: ${reasonText}`);
    return 'done'; // drop from queue — needs manual intervention
  }

  const delay = nextDelayMs(entry.attemptCount - 1);
  entry.nextAttemptAt = Date.now() + delay;
  console.warn(`[${entry.eventId}] ${entry.eventType} -> retry ${entry.attemptCount} scheduled in ${delay}ms. Reason: ${reasonText}`);
  return 'retry';
}

async function pollQueue() {
  const due = queue.filter((e) => e.nextAttemptAt <= Date.now());
  if (due.length === 0) return;

  for (const entry of due) {
    const outcome = await processQueueEntry(entry);
    if (outcome === 'done') {
      queue = queue.filter((e) => e.eventId !== entry.eventId);
    }
  }
  saveQueue(queue);
}

setInterval(pollQueue, QUEUE_POLL_INTERVAL_MS);

// ---------- HTTP endpoint ----------

app.post('/webhook/ies-event', async (req, res) => {
  const {
    webhook_secret,
    event_type: eventType,
    event_id: suppliedEventId,
    table_id: tableId,
    key_field_id: keyFieldId,
    key_value: keyValue,
    field_id: fieldId,
    ...rest
  } = req.body ?? {};

  if (!secretMatches(webhook_secret)) {
    console.warn('Rejected inbound request: bad or missing webhook_secret in body');
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (!eventType || !VALID_EVENT_TYPES.has(eventType)) {
    return res.status(400).json({ error: 'bad_event_type', received: eventType });
  }

  const required = REQUIRED_FIELDS[eventType] ?? [];
  const missing = required.filter((f) => rest[f] === undefined || rest[f] === null);
  if (missing.length > 0) {
    return res.status(400).json({ error: 'missing_fields', fields: missing });
  }

  // Write-back metadata required on every real event, except the ones in
  // EVENTS_WITHOUT_WRITE_BACK (ping has no record; user.deleted's record
  // is gone by the time this fires).
  if (!EVENTS_WITHOUT_WRITE_BACK.has(eventType)) {
    const values = { table_id: tableId, key_field_id: keyFieldId, key_value: keyValue, field_id: fieldId };
    const writeBackMissing = WRITE_BACK_FIELDS.filter((f) => values[f] === undefined || values[f] === null);
    if (writeBackMissing.length > 0) {
      return res.status(400).json({ error: 'missing_write_back_fields', fields: writeBackMissing });
    }
  }

  // user.created requires a real organization object, not just the key present
  if (eventType === 'user.created') {
    const org = rest.organization;
    const orgMissing = ['intuit_org_id', 'name'].filter(
      (f) => typeof org !== 'object' || org === null || org[f] === undefined || org[f] === null || org[f] === ''
    );
    if (orgMissing.length > 0) {
      return res.status(400).json({ error: 'missing_organization_fields', fields: orgMissing });
    }
    // team_leader is optional, but if present it must be a real boolean —
    // Jason's side 400s on a non-boolean anyway, but catching it here gives
    // a clearer error than his generic bad_body would.
    if ('team_leader' in org && typeof org.team_leader !== 'boolean') {
      return res.status(400).json({ error: 'bad_team_leader_value', detail: 'organization.team_leader must be true or false' });
    }
  }

  // Same team_leader type check for user.added_to_org (role promote/demote flag)
  if (eventType === 'user.added_to_org' && 'team_leader' in rest && typeof rest.team_leader !== 'boolean') {
    return res.status(400).json({ error: 'bad_team_leader_value', detail: 'team_leader must be true or false' });
  }

  const eventId = suppliedEventId || crypto.randomUUID();
  const envelope = {
    event_id: eventId,
    event_type: eventType,
    timestamp: new Date().toISOString(),
    data: rest,
  };
  const bodyString = JSON.stringify(envelope); // fixed for this event's lifetime (retries reuse it)

  // First attempt happens synchronously so the Pipeline gets an immediate
  // answer in the common case.
  let sendResult;
  try {
    sendResult = await attemptSend(bodyString);
  } catch (err) {
    console.error(`[${eventId}] ${eventType} -> initial send failed (network):`, err);
    queue.push({
      eventId, eventType, bodyString, tableId, keyFieldId, keyValue, fieldId,
      attemptCount: 1, firstFailedAt: Date.now(), nextAttemptAt: Date.now() + BACKOFF_SCHEDULE_MS[0],
      lastError: String(err),
    });
    saveQueue(queue);
    return res.status(202).json({ event_id: eventId, queued: true, reason: 'network error on first attempt, retrying in background' });
  }

  const { status, result } = sendResult;

  if (status >= 200 && status < 300) {
    console.log(`[${eventId}] ${eventType} -> partner responded ${status}`, result);
    let qbStamp = null;
    if (!EVENTS_WITHOUT_WRITE_BACK.has(eventType)) {
      qbStamp = await stampQuickbaseSuccess({ eventId, eventType, tableId, keyFieldId, keyValue, fieldId });
    }
    return res.status(200).json({ event_id: eventId, partner_status: status, partner_result: result, qb_stamp: qbStamp });
  }

  if (status >= 400 && status < 500) {
    console.error(`[${eventId}] ${eventType} -> partner rejected (${status}), not retrying`, result);
    return res.status(status).json({ event_id: eventId, partner_status: status, partner_result: result, retried: false });
  }

  // 5xx on first attempt -> queue for retry, tell Quickbase it's in flight
  queue.push({
    eventId, eventType, bodyString, tableId, keyFieldId, keyValue, fieldId,
    attemptCount: 1, firstFailedAt: Date.now(), nextAttemptAt: Date.now() + BACKOFF_SCHEDULE_MS[0],
    lastError: `status ${status}`,
  });
  saveQueue(queue);
  console.warn(`[${eventId}] ${eventType} -> partner returned ${status} on first attempt, queued for retry`);
  return res.status(202).json({ event_id: eventId, queued: true, partner_status: status, partner_result: result });
});

// Inspect what's currently queued/retrying — useful since a background
// retry failure is otherwise invisible outside Railway's own logs.
app.get('/queue', (_req, res) => {
  res.json({ pending: queue.length, entries: queue });
});

app.get('/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`IES webhook relay listening on port ${PORT}`));
