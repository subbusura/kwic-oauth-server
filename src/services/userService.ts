import bcrypt from 'bcryptjs';
import User from '../models/User';

const SALT_ROUNDS = 12;

async function register(
  email: string,
  password: string,
  profile?: { name?: string; givenName?: string; surName?: string },
  subAppId?: string
) {
  const exists = await User.findOne({ email });
  if (exists) {
    throw new Error('User already exists');
  }
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await User.create({
    email,
    password_hash: passwordHash,
    password_set: true,
    profile: profile || {},
    registered_app_ids: subAppId ? [subAppId] : []
  });
  return user;
}

async function verifyUser(email: string, password: string) {
  const user = await User.findOne({ email });
  if (!user) {
    throw new Error('Invalid credentials');
  }
  if (!user.password_hash) {
    throw new Error('Invalid credentials');
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    throw new Error('Invalid credentials');
  }
  return user;
}

async function findOrCreateByEmail(email: string) {
  let user = await User.findOne({ email });
  if (!user) {
    user = await User.create({ email, password_hash: '' });
  }
  return user;
}

async function findOrCreateGoogleUser(googleData: { email: string; googleId: string; name?: string; givenName?: string; familyName?: string; picture?: string }) {
  let user = await User.findOne({ google_id: googleData.googleId });
  if (!user) {
    user = await User.findOne({ email: googleData.email });
    if (user) {
      user.google_id = googleData.googleId;
      user.auth_provider = 'google';
      user.profile = { ...user.profile, ...{ name: googleData.name, givenName: googleData.givenName, surName: googleData.familyName, picture: googleData.picture } };
      await user.save();
    } else {
      user = await User.create({
        email: googleData.email,
        google_id: googleData.googleId,
        auth_provider: 'google',
        profile: { name: googleData.name, givenName: googleData.givenName, surName: googleData.familyName, picture: googleData.picture }
      });
    }
  }
  return user;
}

async function updateProfile(userId: string, data: Partial<{
  firstName: string;
  lastName: string;
  name: string;
  preferred_language: string;
  preferred_timezone: string;
  timezone: string;
  phones: { label?: string; country_code?: string; number?: string }[];
  profile_photo_url?: string;
}>) {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  const profile = user.profile || {};
  if (data.name) profile.name = data.name;
  if (data.firstName) profile.givenName = data.firstName;
  if (data.lastName) profile.surName = data.lastName;
  if (data.profile_photo_url) user.profile_photo_url = data.profile_photo_url;
  if (data.preferred_language !== undefined) user.preferred_language = data.preferred_language;
  if (data.preferred_timezone !== undefined) {
    user.preferred_timezone = data.preferred_timezone;
    user.timezone = data.preferred_timezone;
  } else if (data.timezone !== undefined) {
    user.timezone = data.timezone;
  }
  if (data.phones) {
    user.phones = data.phones.filter((p) => p.number) as any;
  }
  user.profile = profile;
  await user.save();
  return user;
}

async function setPassword(userId: string, password: string) {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  user.password_hash = passwordHash;
  user.password_set = true;
  await user.save();
  return user;
}

async function updateSecondaryEmail(userId: string, secondaryEmail: string) {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');
  user.secondary_email = secondaryEmail;
  await user.save();
  return user;
}

async function getById(userId: string) {
  return User.findById(userId);
}

export default {
  register,
  verifyUser,
  findOrCreateByEmail,
  findOrCreateGoogleUser,
  updateProfile,
  setPassword,
  updateSecondaryEmail,
  getById
};
