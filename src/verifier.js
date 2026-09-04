import * as ed from '@noble/ed25519';
import { readFile } from 'node:fs/promises';

const POLICY_FILE = './src/policy.json';
const ISSUER_PUBLIC_KEY_FILE = './private/issuer-public-key.hex';

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Uint8Array.from(Buffer.from(padded, 'base64'));
}

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid public-key data');
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map((part) => parseInt(part, 16)));
}

function result(decision, reasonCode, checks) {
  return { decision, reason_code: reasonCode, checks };
}

function deny(reasonCode, checks) {
  return result('DENY', reasonCode, checks);
}

function allow(checks) {
  return result('ALLOW', 'ALL_REQUIRED_CHECKS_PASSED', checks);
}

function getFixturePath() {
  const index = process.argv.indexOf('--fixture');
  if (index === -1 || !process.argv[index + 1]) {
    throw new Error('Usage: node src/verifier.js --fixture <file> [--holder <did>] [--action <name>]');
  }
  return process.argv[index + 1];
}

function getOption(name, fallback = undefined) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

async function verifySignature(credential, issuerPublicKey) {
  const compactJws = credential.proof?.jws;
  if (!compactJws) return false;
  const parts = compactJws.split('.');
  if (parts.length !== 3) return false;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const { proof, ...currentBody } = credential;
  const currentPayload = Buffer.from(JSON.stringify(currentBody), 'utf8').toString('base64url');
  if (currentPayload !== encodedPayload) return false;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  return ed.verifyAsync(
    base64UrlToBytes(encodedSignature),
    new TextEncoder().encode(signingInput),
    issuerPublicKey
  );
}

async function main() {
  if (process.argv.includes('--help')) {
    console.log('Usage: node src/verifier.js --fixture <file> [--holder <did>] [--action <name>]');
    process.exit(0);
  }

  const policy = JSON.parse(await readFile(POLICY_FILE, 'utf8'));
  const fixturePath = getFixturePath();
  const presentedHolder = getOption('--holder');
  const requestedAction = getOption('--action', 'read-training-lab');

  const credential = JSON.parse(await readFile(fixturePath, 'utf8'));
  const issuerPublicKey = hexToBytes((await readFile(ISSUER_PUBLIC_KEY_FILE, 'utf8')).trim());

  const checks = {
    signature: 'FAIL', issuer: 'FAIL', type: 'FAIL', required_claims: 'FAIL',
    expiry: 'FAIL', status: 'FAIL', subject: 'FAIL', audience: 'FAIL', action: 'FAIL',
  };

  if (!credential || typeof credential !== 'object') {
    console.log(JSON.stringify(deny('MALFORMED_INPUT', checks), null, 2));
    process.exit(1);
  }

  const issuerDid = typeof credential.issuer === 'object' ? credential.issuer.id : credential.issuer;
  if (issuerDid !== policy.acceptedIssuer) {
    console.log(JSON.stringify(deny('ISSUER_NOT_TRUSTED', checks), null, 2));
    process.exit(1);
  }
  checks.issuer = 'PASS';

  if (await verifySignature(credential, issuerPublicKey)) {
    checks.signature = 'PASS';
  } else {
    console.log(JSON.stringify(deny('SIGNATURE_INVALID', checks), null, 2));
    process.exit(1);
  }

  const credentialTypes = Array.isArray(credential.type) ? credential.type : [credential.type];
  if (!credentialTypes.includes(policy.acceptedType)) {
    console.log(JSON.stringify(deny('CREDENTIAL_TYPE_NOT_ACCEPTED', checks), null, 2));
    process.exit(1);
  }
  checks.type = 'PASS';

  const subject = credential.credentialSubject;
  const missingClaim = policy.requiredClaims.find((claim) => subject?.[claim] === undefined);
  if (missingClaim) {
    console.log(JSON.stringify(deny('REQUIRED_CLAIM_MISSING', checks), null, 2));
    process.exit(1);
  }
  checks.required_claims = 'PASS';

  if (credential.validUntil && new Date(credential.validUntil) <= new Date()) {
    console.log(JSON.stringify(deny('CREDENTIAL_EXPIRED', checks), null, 2));
    process.exit(1);
  }
  checks.expiry = 'PASS';

  if (subject.status !== policy.requiredStatus) {
    console.log(JSON.stringify(deny('CREDENTIAL_NOT_ACTIVE', checks), null, 2));
    process.exit(1);
  }
  checks.status = 'PASS';

  if (presentedHolder && subject.id !== presentedHolder) {
    console.log(JSON.stringify(deny('SUBJECT_MISMATCH', checks), null, 2));
    process.exit(1);
  }
  checks.subject = 'PASS';

  if (policy.requireAudience && credential.audience !== policy.endpoint) {
    console.log(JSON.stringify(deny('AUDIENCE_MISMATCH', checks), null, 2));
    process.exit(1);
  }
  checks.audience = 'PASS';

  const permittedActions = subject.permittedActions ?? [];
  if (!policy.allowedActions.includes(requestedAction) || !permittedActions.includes(requestedAction)) {
    console.log(JSON.stringify(deny('ACTION_NOT_ALLOWED', checks), null, 2));
    process.exit(1);
  }
  checks.action = 'PASS';

  console.log(JSON.stringify(allow(checks), null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ decision: 'DENY', reason_code: 'VERIFIER_ERROR', checks: {} }, null, 2));
  process.exit(1);
});
