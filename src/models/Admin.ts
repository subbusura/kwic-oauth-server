import mongoose, { Schema } from 'mongoose';

const AdminSchema = new Schema(
  {
    email: { type: String, unique: true, required: true },
    password_hash: { type: String, required: true },
    role: { type: String, default: 'admin' },
    created_at: { type: Date, default: Date.now }
  },
  { collection: 'admins' }
);

export default mongoose.model('Admin', AdminSchema);
