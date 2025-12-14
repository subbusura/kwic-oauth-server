import mongoose, { Schema } from 'mongoose';

const WebhookSchema = new Schema(
  {
    sub_application_id: { type: Schema.Types.ObjectId, ref: 'SubApplication', required: true },
    event_type: { type: String, required: true },
    callback_url: { type: String, required: true },
    secret_enc: { type: String, required: true },
    active: { type: Boolean, default: true },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'webhooks' }
);

export default mongoose.model('Webhook', WebhookSchema);
