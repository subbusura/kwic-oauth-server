import mongoose, { Schema } from 'mongoose';

const IdpConsentSchema = new Schema(
  {
    user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    sp_entity_id: { type: String, required: true },
    granted_at: { type: Date, default: Date.now }
  },
  { collection: 'idp_consents' }
);

export default mongoose.model('IdpConsent', IdpConsentSchema);
