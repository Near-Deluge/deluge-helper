const { ecEncrypt, ecDecrypt } = require("../index");
const assert = require("assert");

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

    assert.deepStrictEqual(descryptedStr, randomData, "Data and Decrypted Data doesn't matched!!");
    
  });
});
