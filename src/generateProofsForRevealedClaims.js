import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';

function generateProofsForRevealedClaims(claimsJsonFilePath, revealedClaims) {
  // Convert the claims object into an array of strings (key:value) for the leaves
   // Read claims JSON file
   const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));

   // Convert the claims object into an array of strings (key:value) for the leaves
   const leaves = Object.entries(claimsData).map(([key, value]) =>
     sha256(`${value}`)
   );

  // Create the Merkle tree
  const tree = new MerkleTree(leaves, sha256, { sortPairs: true });

  // Generate proofs for the revealed claims
  const proofs = revealedClaims.reduce((acc, claimKey) => {
    const claimValue = claimsData[claimKey];
    const claimString = sha256(`${claimValue}`);
    const proof = tree.getProof(claimString).map(p => ({
      position: p.position,
      data: p.data.toString('hex')
    }));

    // Store the claim and its proof
    acc[claimKey] = {
      value: claimValue,
      proof
    };

    return acc;
  }, {});

  // Prepare the output object
  const output = {
    revealedClaims: proofs
  };

  // Write the output to a JSON file
  const outputFilename = `revealedClaims_${claimsJsonFilePath.replace(/^.*[\\/]/, '')}`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Revealed claims and their proofs have been saved to ${outputFilename}`);
}


export default generateProofsForRevealedClaims;