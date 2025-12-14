import axios from 'axios';
import { Queue } from 'bullmq';
import Webhook from '../models/Webhook';
import { redis } from '../config';

const webhookQueue = new Queue('webhookDelivery', { connection: redis });

async function listWebhooks() {
  return Webhook.find();
}

async function createWebhook(payload: any) {
  return Webhook.create(payload);
}

async function updateWebhook(id: string, payload: any) {
  return Webhook.findByIdAndUpdate(id, payload, { new: true });
}

async function deleteWebhook(id: string) {
  return Webhook.findByIdAndDelete(id);
}

async function enqueueEvent(payload: any) {
  await webhookQueue.add('deliver', payload, {
    attempts: 5,
    backoff: { type: 'exponential', delay: 2000 }
  });
}

async function dispatchDirect(url: string, body: any, headers: Record<string, string>) {
  await axios.post(url, body, { headers });
}

export default {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  enqueueEvent,
  dispatchDirect
};
