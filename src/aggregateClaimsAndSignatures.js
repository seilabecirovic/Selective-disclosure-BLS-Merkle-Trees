import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';


async function aggregateClaimsAndSignatures(claimsFiles, rootSignatureFiles) {
  // Initialize the BLS library
  
  var bls = await loadBls();


  let aggregatedClaims = [];
  let signatures = [];

  // Process disclosed claims and proofs
  claimsFiles.forEach(filePath => {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    aggregatedClaims.push(data.revealedClaims);
  });

  // Process roots and signatures, and collect signatures for aggregation
  rootSignatureFiles.forEach(filePath => {
    const { issuer, signature } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    signatures.push(signature);
  });

  // Convert signatures from hex to Signature objects
  signatures = signatures.map(sigHex => bls.G2Element.fromBytes(Buffer.from(sigHex, 'hex')));

  // Aggregate the signatures
  const aggregatedSignature = bls.AugSchemeMPL.aggregate(signatures);

  // Prepare the output object
  const output = {
    aggregatedClaims,
    aggregatedSignature: Buffer.from(aggregatedSignature.serialize()).toString('hex')
  };

  // Write the aggregated data to a JSON file
  const outputFilename = 'aggregatedClaimsAndSignatures.json';
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Aggregated data saved to ${outputFilename}`);
}

// Example usage
export default aggregateClaimsAndSignatures;