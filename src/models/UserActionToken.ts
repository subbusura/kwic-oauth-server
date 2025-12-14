import mongoose, { Schema } from 'mongoose';

type TokenType = 'password_reset' | 'email_verification' | 'password_change';

const UserActionTokenSchema = new Schema(
  {
    user_id: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    token_hash: { type: String, required: true, unique: true },
    type: {
      type: String,
      enum: ['password_reset', 'email_verification', 'password_change'],
      required: true,
      index: true
    },
    expires_at: { type: Date, required: true, index: true },
    used_at: { type: Date, default: null },
    last_sent_at: { type: Date, default: Date.now },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'user_action_tokens' }
);

UserActionTokenSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model('UserActionToken', UserActionTokenSchema);
export type { TokenType };
