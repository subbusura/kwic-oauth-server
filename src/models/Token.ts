import mongoose, { Schema } from 'mongoose';

const TokenSchema = new Schema(
  {
    client_id: { type: String, index: true },
    user_id: { type: Schema.Types.ObjectId, ref: 'User' },
    sub_application_id: { type: Schema.Types.ObjectId, ref: 'SubApplication' },
    scope: [String],
    jti: { type: String, index: true },
    token_type: { type: String, default: 'access' },
    access_token_hash: String,
    refresh_token_hash: String,
    revoked: { type: Boolean, default: false },
    issued_at: Date,
    expires_at: Date
  },
  { collection: 'tokens' }
);

export default mongoose.model('Token', TokenSchema);
