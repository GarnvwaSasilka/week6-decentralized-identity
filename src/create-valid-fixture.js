import * as ed from '@noble/ed25519';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { base58btc } from 'multiformats/bases/base58';

const ISSUER_PRIVATE_KEY_FILE = './private/issuer-private-key.hex';
const ISSUER_PUBLIC_KEY_FILE = './private/issuer-public-key.hex';
const HOLDER_PUBLIC_KEY_FILE = './private/holder-public-key.hex';
const OUTPUT_FILE = './src/test-fixtures/valid.json';

function hexToBytes(hex) {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid hexadecimal key material');
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map((part) => parseInt(part, 16)));
}

function publicKeyToDid(publicKey) {
  const bytes = new Uint8Array(2 + publicKey.length);
  bytes.set([0xed, 0x01], 0);
  bytes.set(publicKey, 2);
  return `did:key:${base58btc.encode(bytes)}`;
}

function bytesToBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

async function main() {
  await mkdir('./src/test-fixtures', { recursive: true });

  const issuerPrivateKey = hexToBytes((await readFile(ISSUER_PRIVATE_KEY_FILE, 'utf8')).trim());
  const issuerPublicKey = hexToBytes((await readFile(ISSUER_PUBLIC_KEY_FILE, 'utf8')).trim());
  const holderPublicKey = hexToBytes((await readFile(HOLDER_PUBLIC_KEY_FILE, 'utf8')).trim());

  const issuerDid = publicKeyToDid(issuerPublicKey);
  const issuerFingerprint = issuerDid.slice('did:key:'.length);
  const verificationMethod = `${issuerDid}#${issuerFingerprint}`;
  const holderDid = publicKeyToDid(holderPublicKey);

  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const credentialBody = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IhifixTrainingCredential'],
    issuer: { id: issuerDid, name: 'Ihifix Training Authority' },
    validFrom: new Date().toISOString(),
    validUntil: expires.toISOString(),
    audience: '/training-access',
    credentialSubject: {
      id: holderDid,
      course: 'Application Security Foundations',
      cohort: 'Cohort 2',
      status: 'active',
      permittedActions: ['read-training-lab'],
    },
  };

  const protectedHeader = { alg: 'EdDSA', typ: 'VC-CLASSROOM-JWS', kid: verificationMethod };
  const encodedHeader = Buffer.from(JSON.stringify(protectedHeader), 'utf8').toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(credentialBody), 'utf8').toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await ed.signAsync(new TextEncoder().encode(signingInput), issuerPrivateKey);

  const credential = {
    ...credentialBody,
    proof: {
      type: 'Ed25519Signature2020',
      proofPurpose: 'assertionMethod',
      verificationMethod,
      jws: `${signingInput}.${bytesToBase64Url(signature)}`,
    },
  };

  await writeFile(OUTPUT_FILE, `${JSON.stringify(credential, null, 2)}\n`);
  console.log('Valid Class 2 fixture created.');
  console.log('Holder DID:', holderDid);
}

main().catch((err) => console.error(err.message));
