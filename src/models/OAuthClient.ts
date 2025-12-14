import mongoose, { Schema } from 'mongoose';

const OAuthClientSchema = new Schema(
  {
    sub_application_id: { type: Schema.Types.ObjectId, ref: 'SubApplication', required: true },
    client_id: { type: String, unique: true, required: true },
    client_secret_enc: { type: String, required: true },
    client_type: { type: String, enum: ['confidential', 'public'], default: 'confidential' },
    grant_types: [String],
    redirect_uris: [String],
    scopes: [String],
    status: { type: String, default: 'active' },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'oauth_clients' }
);

export default mongoose.model('OAuthClient', OAuthClientSchema);
