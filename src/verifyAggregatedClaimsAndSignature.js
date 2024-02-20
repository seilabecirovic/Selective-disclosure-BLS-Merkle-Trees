import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';

async function verifyClaims(revealedClaims, rootSignatureFilePath, publicKeyFilePath) {
    // Initialize the BLS library
   
    var bls = await loadBls();
  
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
  
    return isValidClaims && isValidSignature
  }
  


async function verifyAggregatedClaimsAndSignature(aggregatedFilePath, publicKeyFiles, rootSignatureFiles) {
    // Initialize the BLS library


    var bls = await loadBls();
    // Read the aggregated claims and signature
    const { aggregatedClaims, aggregatedSignature } = JSON.parse(fs.readFileSync(aggregatedFilePath, 'utf8'));
    const aggregatedSignatureBytes = Buffer.from(aggregatedSignature, 'hex');
    const aggregatedSignatures = bls.G2Element.from_bytes(aggregatedSignatureBytes)
    
    //Check each single validity
    for (let i = 0; i < rootSignatureFiles.length; i++) {
        const isValidClaim = await verifyClaims(aggregatedClaims[i],rootSignatureFiles[i], publicKeyFiles[i]);
        console.log(`Verification of claim and signature ${i + 1}: ${isValidClaim}`);
    }
    
    // Aggregate all public keys
    let publicKeys = [];
    for (const filePath of publicKeyFiles) {
        const { publicKey } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const publicKeyBytes = bls.G1Element.from_bytes(Buffer.from(publicKey, 'hex'));
        publicKeys.push(publicKeyBytes);
    }

    // Aggregate all roots for final verification
    let roots = [];
    for (const filePath of rootSignatureFiles) {
        const { merkleRoot } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        roots.push(merkleRoot);
    }

    // Verify the aggregated signature with the aggregated public key
    const isValid = bls.AugSchemeMPL.aggregate_verify(publicKeys,roots, aggregatedSignatures);

    console.log(`Aggregated signature verification result: ${isValid}`);
}

export default verifyAggregatedClaimsAndSignature;