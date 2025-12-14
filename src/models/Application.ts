import mongoose, { Schema } from 'mongoose';

const ApplicationSchema = new Schema(
  {
    name: { type: String, required: true },
    description: String,
    origins: [String],
    launch_url: { type: String },
    launch_path: { type: String },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'applications' }
);

export default mongoose.model('Application', ApplicationSchema);
