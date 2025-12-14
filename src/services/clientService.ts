import bcrypt from 'bcryptjs';
import cryptoRandomString from 'crypto-random-string';
import Application from '../models/Application';
import SubApplication from '../models/SubApplication';
import OAuthClient from '../models/OAuthClient';

const SALT_ROUNDS = 12;

async function listApplications() {
  return Application.find();
}

async function createApplication(payload: any) {
  return Application.create(payload);
}

async function updateApplication(id: string, payload: any) {
  return Application.findByIdAndUpdate(id, payload, { new: true });
}

async function deleteApplication(id: string) {
  return Application.findByIdAndDelete(id);
}

async function listSubApplications() {
  return SubApplication.find();
}

async function createSubApplication(payload: any) {
  return SubApplication.create(payload);
}

async function updateSubApplication(id: string, payload: any) {
  return SubApplication.findByIdAndUpdate(id, payload, { new: true });
}

async function deleteSubApplication(id: string) {
  return SubApplication.findByIdAndDelete(id);
}

async function listClients() {
  return OAuthClient.find();
}

async function createClient(payload: any) {
  const clientSecret = payload.client_secret || cryptoRandomString({ length: 48 });
  const clientSecretEnc = await bcrypt.hash(clientSecret, SALT_ROUNDS);
  const doc = await OAuthClient.create({
    ...payload,
    client_secret_enc: clientSecretEnc
  });
  // Return plaintext secret only once
  const json = doc.toObject();
  return { ...json, client_secret: clientSecret };
}

async function updateClient(id: string, payload: any) {
  return OAuthClient.findByIdAndUpdate(id, payload, { new: true });
}

async function deleteClient(id: string) {
  return OAuthClient.findByIdAndDelete(id);
}

export default {
  listApplications,
  createApplication,
  updateApplication,
  deleteApplication,
  listSubApplications,
  createSubApplication,
  updateSubApplication,
  deleteSubApplication,
  listClients,
  createClient,
  updateClient,
  deleteClient
};
