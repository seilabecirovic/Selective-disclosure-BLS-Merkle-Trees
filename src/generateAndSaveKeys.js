
import loadBls from "bls-signatures";
import fs  from 'fs';
import crypto from 'crypto';



async function generateAndSaveKeys(issuerName) {


  var bls = await loadBls();
  // Generate a private key
  const privateKey = bls.AugSchemeMPL.key_gen(crypto.randomBytes(32));

  // Get the public key from the private key
  const publicKey = privateKey.get_g1();

  // Convert keys to hexadecimal strings for storage
  const privateKeyHex = bls.Util.hex_str(privateKey.serialize());
  const publicKeyHex = bls.Util.hex_str(publicKey.serialize());

  // Prepare objects to write to JSON, including the issuer name
  const privateKeyObj = { issuer: issuerName, privateKey: privateKeyHex };
  const publicKeyObj = { issuer: issuerName, publicKey: publicKeyHex };

  // Filenames include the issuer name for uniqueness
  const privateKeyFilename = `${issuerName}_privateKey.json`;
  const publicKeyFilename = `${issuerName}_publicKey.json`;

  // Write the private key to a JSON file
  fs.writeFile(privateKeyFilename, JSON.stringify(privateKeyObj, null, 2), (err) => {
    if (err) throw err;
    console.log('Private key has been saved to ' + privateKeyFilename);
  });

  // Write the public key to a JSON file
  fs.writeFile(publicKeyFilename, JSON.stringify(publicKeyObj, null, 2), (err) => {
    if (err) throw err;
    console.log('Public key has been saved to ' + publicKeyFilename);
  });
}

export default generateAndSaveKeys;
