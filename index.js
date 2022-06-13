const {
  createHash,
  createHmac,
  createECDH,
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require("crypto");
const { isHex, hexToUint8Array, concatUint8Arrays } = require("./util");
const curve25519 = require("curve25519-js");
const ed2curve = require("ed2curve");
const { generateSeedPhrase } = require("near-seed-phrase");

const deriveSecret = (sharedKey) => {
  if (typeof sharedKey !== "string" && !(sharedKey instanceof Uint8Array)) {
    throw "'sharedKey' must be a string or Uint8Array";
  }

  if (typeof sharedKey == "string") {
    if (isHex(sharedKey)) {
      sharedKey = hexToUint8Array(sharedKey);
    } else {
      throw "'sharedKey' must be an hexadecimal string";
    }
  }

  const pseudoRandomKey = createHash("sha256").update(sharedKey).digest();

  const iv = createHmac("sha256", pseudoRandomKey)
    .update("0")
    .digest()
    .slice(0, 32);

  const aesKey = createHmac("sha256", iv).update("1").digest().slice(0, 32);

  return {
    iv,
    aesKey,
  };
};

const aesAuthEncrypt = (data, aesKey, iv) => {
  let cipher = createCipheriv("aes-256-gcm", aesKey, iv);

  let encrypted = cipher.update(data);
  encrypted = concatUint8Arrays([encrypted, cipher.final()]);

  return { tag: new Uint8Array(cipher.getAuthTag()), encrypted: encrypted };
};

const aesAuthDecrypt = (encrypted, aesKey, iv, tag) => {
  let decipher = createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(tag);

  let decryptedBuffers = [decipher.update(encrypted)];

  return concatUint8Arrays(decryptedBuffers);
};

const encrypt_data = (data) => {
  if (typeof data !== "string") {
    throw "Data Needs to be of Type String";
  }

  const wallet_enc_key = randomBytes(32);

  // Double Hash aes Key to get iv: using on 0:16 bytes of it
  const h1 = createHash("sha256").update(wallet_enc_key).digest();
  const iv = createHash("sha256").update(h1).digest().slice(0, 16);

  const cipher = createCipheriv("aes-256-gcm", wallet_enc_key, iv);
  let encrypted = cipher.update(data);

  return {
    walletEncKey: wallet_enc_key,
    encryptedData: Buffer.concat([encrypted, cipher.final()]),
  };
};

// encryt aes key
// Params: aes_key, publickey

const encrypt_key = (walletEncKey, publicKey) => {
  if (!(walletEncKey instanceof Uint8Array)) {
    throw "Wallet encryption key must be Uint8Array ";
  }

  if (
    (typeof publicKey !== "string" || !isHex(publicKey)) &&
    !(publicKey instanceof Uint8Array)
  ) {
    throw "Public Key must be a hex String or Uint8Array";
  }

  if (typeof publicKey === "string") {
    publicKey = hexToUint8Array(publicKey);
  }

  const { public: ephemeralPublicKey, private: ephemeralPrivateKey } =
    curve25519.generateKeyPair(randomBytes(32));

  const curve25519pub = ed2curve.convertPublicKey(publicKey);

  var sharedKey = curve25519.sharedKey(ephemeralPrivateKey, curve25519pub);

  var { aesKey, iv } = deriveSecret(sharedKey);

  const { encrypted, tag } = aesAuthEncrypt(walletEncKey, aesKey, iv);

  return {
    encryptedKey: encrypted,
    authTag: tag,
    publicKey: ephemeralPublicKey,
  };
};

const decrypt_key = (encryptedKey, ephemeralPubKey, authTag, privateKey) => {
  if (
    (typeof ephemeralPubKey !== "string" || !isHex(ephemeralPubKey)) &&
    !(ephemeralPubKey instanceof Uint8Array)
  ) {
    throw "Ephermal Public Key must be a hex String or a Uint8Array";
  }

  const curve25519pv = ed2curve.convertSecretKey(privateKey);

  var sharedKey = curve25519.sharedKey(curve25519pv, ephemeralPubKey);

  var { aesKey, iv } = deriveSecret(sharedKey);

  let res = aesAuthDecrypt(encryptedKey, aesKey, iv, authTag);

  return {
    aesKey: res,
  };
};

const decrypt_data = (encrypted_data, encryption_key) => {
  const h1 = createHash("sha256").update(encryption_key).digest();
  const iv = createHash("sha256").update(h1).digest().slice(0, 16);

  const decipher = createDecipheriv("aes-256-gcm", encryption_key, iv);
  let decryptedBuffers = [decipher.update(encrypted_data)];

  return {
    decrypted: decryptedBuffers,
  };
};

/**
 * Encrypts data from a public key using ephermal keys internally
 * @param {string | Uint8Array} data Data which needs to be encrypted
 * @param {string | Uint8Array} publicKey Public Key whose private key will be required for decryption
 */
const ecEncrypt = (data, publicKey) => {
  if (
    (typeof publicKey !== "string" || !isHex(publicKey)) &&
    !(publicKey instanceof Uint8Array)
  ) {
    throw "Public Key must be a hex String or a Uint8Array";
  }

  if (typeof publicKey === "string") {
    publicKey = hexToUint8Array(publicKey);
  }

  if (typeof data !== "string") {
    throw "Data Needs to be of Type String ";
  }

  const { encryptedData, walletEncKey } = encrypt_data(data);

  const {
    encryptedKey,
    authTag,
    publicKey: ephPubKey,
  } = encrypt_key(walletEncKey, publicKey);

  return {
    encryptedData,
    encryptedKey,
    authTag,
    ephPubKey,
  };
};

/**
 * Decrypts Encrypted data from Encrypted Data Encryption Key
 * @param {string | Uint8Array} encryptedData Data which needs to be decrypted
 * @param {string | Uint8Array} encryptedKey Ecnrypted Key which has encrypted data
 * @param {string | Uint8Array} ephemeralPubKey PublicKey to whose common point encryptedKey was encrypted
 * @param {string | Uint8Array} authTag Authentication Tag to encryption of encryption key
 * @param {string | Uint8Array} privateKey Private Key to which public key encrypted key was decoded
 */
const ecDecrypt = (
  encryptedData,
  encryptedKey,
  ephemeralPubKey,
  authTag,
  privateKey
) => {
  if (
    (typeof privateKey !== "string" || !isHex(privateKey)) &&
    !(privateKey instanceof Uint8Array)
  ) {
    throw "Private Key must be a hex String or a Uint8Array";
  }

  if (typeof privateKey === "string") {
    privateKey = hexToUint8Array(privateKey);
  }

  if (
    (typeof ephemeralPubKey !== "string" || !isHex(ephemeralPubKey)) &&
    !(ephemeralPubKey instanceof Uint8Array)
  ) {
    throw "Ephermal Public Key must be a hex String or a Uint8Array";
  }

  if (typeof ephemeralPubKey === "string") {
    ephemeralPubKey = hexToUint8Array(ephemeralPubKey);
  }

  if (
    (typeof encryptedData !== "string" || !isHex(encryptedData)) &&
    !(encryptedData instanceof Uint8Array)
  ) {
    throw "Encrypted Data must be a hex String or a Uint8Array";
  }

  if (typeof encryptedData === "string") {
    encryptedData = hexToUint8Array(encryptedData);
  }

  if (
    (typeof encryptedKey !== "string" || !isHex(encryptedKey)) &&
    !(encryptedKey instanceof Uint8Array)
  ) {
    throw "Encrypted Key must be a hex String or a Uint8Array";
  }

  if (typeof encryptedKey === "string") {
    encryptedKey = hexToUint8Array(encryptedKey);
  }

  if (
    (typeof authTag !== "string" || !isHex(authTag)) &&
    !(authTag instanceof Uint8Array)
  ) {
    throw "Auth tag Key must be a hex String or a Uint8Array";
  }

  if (typeof authTag === "string") {
    authTag = hexToUint8Array(authTag);
  }
  const { aesKey } = decrypt_key(
    encryptedKey,
    ephemeralPubKey,
    authTag,
    privateKey
  );

  const decrypted_data = decrypt_data(encryptedData, aesKey);

  return decrypted_data;
};

/**
 * Generates a new ed25519 Keypair
 * @param {string} seed Seed which will be used to generate Keypair
 */
const genKeyPair = (seed) => {
  if (typeof seed !== "string") {
    throw "Seed must be a string";
  }

  // Convert it to sha256 hash as ed25519 expects a 32byte length
  const seedHash = createHash("sha256").update(seed).digest();

  const { public, private } = curve25519.generateKeyPair(seedHash);

  return {
    pubKey: public,
    privKey: private,
  };
};

/**
 * Generates a new Keypair with seed phrases used to Generate the keypair
 */
const generateRandomKeypair = () => {
  return generateSeedPhrase()
}

module.exports.generateRandomKeypair = generateRandomKeypair;
module.exports.genKeyPair = genKeyPair;
module.exports.ecDecrypt = ecDecrypt;
module.exports.ecEncrypt = ecEncrypt;
