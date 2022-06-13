const { ecEncrypt, ecDecrypt, genKeyPair, generateRandomKeypair } = require("../index");
const assert = require("assert");
const bs58 = require("bs58");

describe("index.js", () => {
  it("should encrypt and decrypt", () => {
    const randomData = JSON.stringify({
      data: "This is a testing value.",
    });

    const samplePubKey =
      "da202062e68f3a7f156142e360665c0550b6923c385c7ee109a0a1141f022dff";
    const samplePrivKey =
      "5a7131f14fecbbc3fe99967596c82af0a004437a86740888002714e3541358e6da202062e68f3a7f156142e360665c0550b6923c385c7ee109a0a1141f022dff";

    const pubObj = ecEncrypt(randomData, samplePubKey);

    const decData = ecDecrypt(
      pubObj.encryptedData,
      pubObj.encryptedKey,
      pubObj.ephPubKey,
      pubObj.authTag,
      samplePrivKey
    );

    const descryptedStr = decData.decrypted.toString();

    assert.deepStrictEqual(
      descryptedStr,
      randomData,
      "Data and Decrypted Data doesn't matched!!"
    );
  });

  it("should generate keypair", () => {
    const seed = "0001";

    const { pubKey, privKey } = genKeyPair(seed);

    const privKeyP =
      "888b19a43b151683c87895f6211d9f8640f97bdc8ef32f03dbe057c8f5e56d72";
    const pubKeyP =
      "b972e4f265e397e4e9f9f1c1de5e0f51f8197e28cbfd4b685c09d98af937ef75";

    const pubKeyHex = Buffer.from(pubKey).toString("hex");
    const privKeyHex = Buffer.from(privKey).toString("hex");

    assert.deepStrictEqual(privKeyHex, privKeyP, "Private Key does not match!!");
    assert.deepStrictEqual(pubKeyHex, pubKeyP, "Public Key does not match!!");
  });

  it("should encrypt and decrypt with generateRandomKeypairs's keys", () => {

    const { publicKey, secretKey} = generateRandomKeypair();

    const randomData = JSON.stringify({
      data: "This is a testing value.",
    });

    const pubKey = bs58.decode(publicKey.split("ed25519:")[1]);
    const privKey = bs58.decode(secretKey.split("ed25519:")[1]);

    const pubObj = ecEncrypt(randomData, pubKey);

    const decData = ecDecrypt(
      pubObj.encryptedData,
      pubObj.encryptedKey,
      pubObj.ephPubKey,
      pubObj.authTag,
      privKey
    );

    const descryptedStr = decData.decrypted.toString();

    assert.deepStrictEqual(
      descryptedStr,
      randomData,
      "Data and Decrypted Data doesn't matched!!"
    );

  })

});
