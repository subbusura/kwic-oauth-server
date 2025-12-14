import mongoose, { Schema } from 'mongoose';

const PhoneSchema = new Schema(
  {
    label: { type: String },
    country_code: { type: String },
    number: { type: String }
  },
  { _id: false }
);

const UserSchema = new Schema(
  {
    email: { type: String, unique: true, required: true },
    secondary_email: { type: String },
    email_verified: { type: Boolean, default: false },
    password_hash: { type: String },
    password_set: { type: Boolean, default: false },
    sub_application_id: { type: Schema.Types.ObjectId, ref: 'SubApplication' },
    profile_photo_url: { type: String },
    preferred_language: { type: String },
    preferred_timezone: { type: String },
    timezone: { type: String },
    registered_app_ids: [{ type: Schema.Types.ObjectId, ref: 'Application' }],
    phones: [PhoneSchema],
    profile: Schema.Types.Mixed,
    google_id: { type: String, sparse: true, unique: true },
    auth_provider: { type: String, enum: ['local', 'google'], default: 'local' },
    aws_roles: [{ type: String }],
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'users' }
);

export default mongoose.model('User', UserSchema);
