import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';


async function verifyClaims(proofsFilePath, rootSignatureFilePath, publicKeyFilePath) {
  // Initialize the BLS library
 console.log(proofsFilePath)
  var bls = await loadBls();

  // Read and parse the proofs file
  const { revealedClaims } = JSON.parse(fs.readFileSync(proofsFilePath, 'utf8'));

  // Read and parse the root and signature file
  const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));

  // Read and parse the public key file
  const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
  const publicKeyHex = publicKeyData.publicKey;
  const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex,'hex'));
 
  // Verify each claim
  const tree = new MerkleTree([], sha256, { sortPairs: true }); // Dummy tree for verification
  const isValidClaims =  Object.entries(revealedClaims).every(([key, { value, proof }]) => {
    const leaf = sha256(`${value}`);
    const proofObjects = proof.map(p => ({ position: p.position, data: Buffer.from(p.data, 'hex') }));
    return tree.verify(proofObjects, leaf, merkleRoot);
  });
  // Verify the signature
  const isValidSignature = bls.AugSchemeMPL.verify(publicKey,
    merkleRoot,
    bls.G2Element.from_bytes(Buffer.from(signature, 'hex'))
  );

  console.log(`Claims are valid: ${isValidClaims}`);
  console.log(`Signature is valid: ${isValidSignature}`);
}

export default verifyClaims;