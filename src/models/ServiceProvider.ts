import mongoose, { Schema } from 'mongoose';

const ServiceProviderSchema = new Schema(
  {
    name: { type: String, required: true },
    entity_id: { type: String, required: true, unique: true },
    acs_url: { type: String, required: true },
    certificate: String,
    sign_assertion: { type: Boolean, default: true },
    sign_response: { type: Boolean, default: true },
    require_consent: { type: Boolean, default: true },
    metadata_xml: String,
    attributes: [
      {
        name: String,
        source: String // e.g., email, name, profile.custom
      }
    ],
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'service_providers' }
);

export default mongoose.model('ServiceProvider', ServiceProviderSchema);
