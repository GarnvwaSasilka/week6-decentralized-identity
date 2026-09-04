import { test } from 'node:test';
import assert from 'node:assert';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const validFixture = JSON.parse(readFileSync('src/test-fixtures/valid.json', 'utf8'));
const VALID_HOLDER_DID = validFixture.credentialSubject.id;

function runVerifier(fixture, holder = VALID_HOLDER_DID, action = 'read-training-lab') {
  try {
    const output = execSync(
      `node src/verifier.js --fixture ${fixture} --holder "${holder}" --action "${action}"`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] }
    );
    return JSON.parse(output);
  } catch (err) {
    return JSON.parse(err.stdout);
  }
}

test('Valid credential should yield ALLOW', () => {
  const res = runVerifier('src/test-fixtures/valid.json');
  assert.strictEqual(res.decision, 'ALLOW');
});

test('Invalid signature should yield SIGNATURE_INVALID', () => {
  const res = runVerifier('src/test-fixtures/tampered.json');
  assert.strictEqual(res.reason_code, 'SIGNATURE_INVALID');
});

test('Untrusted issuer should yield ISSUER_NOT_TRUSTED', () => {
  const res = runVerifier('src/test-fixtures/untrusted-issuer.json');
  assert.strictEqual(res.reason_code, 'ISSUER_NOT_TRUSTED');
});

test('Expired credential should yield CREDENTIAL_EXPIRED', () => {
  const res = runVerifier('src/test-fixtures/expired.json');
  assert.strictEqual(res.reason_code, 'CREDENTIAL_EXPIRED');
});

test('Missing claim should yield REQUIRED_CLAIM_MISSING', () => {
  const res = runVerifier('src/test-fixtures/missing-claim.json');
  assert.strictEqual(res.reason_code, 'REQUIRED_CLAIM_MISSING');
});

test('Unauthorized action should yield ACTION_NOT_ALLOWED', () => {
  const res = runVerifier('src/test-fixtures/valid.json', VALID_HOLDER_DID, 'delete-root-database');
  assert.strictEqual(res.reason_code, 'ACTION_NOT_ALLOWED');
});
