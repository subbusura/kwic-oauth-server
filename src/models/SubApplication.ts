import mongoose, { Schema } from 'mongoose';

const SubApplicationSchema = new Schema(
  {
    application_id: { type: Schema.Types.ObjectId, ref: 'Application', required: true },
    name: { type: String, required: true },
    redirect_uris: [String],
    allow_registration: { type: Boolean, default: true },
    allow_password_login: { type: Boolean, default: true },
    enabled_providers: [String],
    saml: {
      enabled: { type: Boolean, default: false },
      idp_entity_id: String,
      sso_url: String,
      certificate: String,
      sign_request: { type: Boolean, default: true },
      email_attribute: { type: String, default: 'email' }
    },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'sub_applications' }
);

export default mongoose.model('SubApplication', SubApplicationSchema);
