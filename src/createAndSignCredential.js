import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';
import path  from 'path';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js'
import { stringToBigInt } from './utils.js';
const CommitmentUtils = bulletproofs.CommitmentUtils;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const Rand = bulletproofs.Rand;
const GeneratorParams = bulletproofs.GeneratorParams;
const library = "elliptic"
const curveName = "secp256k1";
const CompressedBulletproof = bulletproofs.CompressedProofs;
const ProofFactory = bulletproofs.ProofFactory;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);
const PointFn = pedGenParams.PointFn;


async function createAndSignCredential(claimsJsonFilePath, privateKeyJsonFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read claims JSON file
  const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));

  const salt = Rand.randUnder(pedGenParams.n);
  // Convert the claims object into an array of strings (key:value) for the leaves
  const leaves = Object.entries(claimsData).map(([key, value]) =>{
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value = BigInt(Math.round(value));
    
    return PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, salt,pedGenParams))
    }
  );

  // Create the Merkle tree
  const tree = new MerkleTree(leaves, sha256, { sortPairs: true });

  // Get the Merkle root
  const root = tree.getRoot().toString('hex');

  // Read private key JSON file
  const privateKeyData = JSON.parse(fs.readFileSync(privateKeyJsonFilePath, 'utf8'));
  const privateKeyHex = privateKeyData.privateKey;

  // Convert the private key back to a BLS PrivateKey object
  const privateKey = bls.PrivateKey.fromBytes(Buffer.from(privateKeyHex, 'hex'),false);

  const signature = bls.AugSchemeMPL.sign(privateKey, root);
  // Sign the root with the private key
  //const signature = privateKey.sign(Buffer.from(root, 'hex'));

  // Convert the signature to hexadecimal for storage
  const signatureHex = bls.Util.hex_str(signature.serialize());

  // Prepare the output JSON object
  const output = {
    issuer: privateKeyData.issuer,
    merkleRoot: root,
    signature: signatureHex
  };

  const output2 = {
    claims: claimsData,
    issuer: privateKeyData.issuer,
    salt: salt.toString()
  }

  // Write the output to a JSON file
  const outputFilename = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_signature.json`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');
  
  const outputFilename2 = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_issued_credential.json`;
  fs.writeFileSync(outputFilename2, JSON.stringify(output2, null, 2), 'utf8');

  console.log(`Merkle root signed. Output saved to ${outputFilename}. Credential saved to ${outputFilename2}`);
}

export default createAndSignCredential;