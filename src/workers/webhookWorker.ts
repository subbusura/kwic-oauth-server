import { Worker } from 'bullmq';
import axios from 'axios';
import Webhook from '../models/Webhook';
import { redis } from '../config';
import { signHMAC } from '../lib/hmac';
import logger from '../lib/logger';

const worker = new Worker(
  'webhookDelivery',
  async (job) => {
    const { webhookId, eventId, payload } = job.data;
    const webhook = await Webhook.findById(webhookId);
    if (!webhook || !webhook.active) {
      return;
    }

    const body = JSON.stringify(payload);
    const signature = signHMAC(webhook.secret_enc, body);
    await axios.post(webhook.callback_url, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Event-Id': eventId,
        'X-SubApp-Id': String(webhook.sub_application_id),
        'X-Signature': signature
      },
      timeout: 5000
    });
  },
  { connection: redis }
);

worker.on('failed', (job, err) => {
  logger.warn('Webhook job failed', { jobId: job.id, err: err.message });
});

worker.on('completed', (job) => {
  logger.info('Webhook job completed', { jobId: job.id });
});
