import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js'
import { closestPowerOfTwo, stringToBigInt } from './utils.js';
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


function generateProofsForRevealedClaims(claimsJsonFilePath, revealedClaimsFilePath) {
  // Convert the claims object into an array of strings (key:value) for the leaves
   // Read claims JSON file
   const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));
   const revealedClaims = JSON.parse(fs.readFileSync(revealedClaimsFilePath, 'utf8'));
   // Convert the claims object into an array of strings (key:value) for the leaves
  
   const leaves = Object.entries(claimsData.claims).map(([key, value]) =>{
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value = BigInt(Math.round(value))
    return PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, BigInt(claimsData.salt),pedGenParams))
    }
  );
  // Create the Merkle tree
  const tree = new MerkleTree(leaves, sha256, { sortPairs: true });
  // Generate proofs for the revealed claims
  const proofs = revealedClaims.disclosedClaims?.reduce((acc, claimKey) => {
    const claimValue = claimsData.claims[claimKey];
    var value = claimValue;
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
    value = BigInt(Math.round(value));
    var salt = BigInt(claimsData.salt)
    const claimString= PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, salt,pedGenParams))
    const proof = tree.getProof(claimString).map(p => ({
      position: p.position,
      data: p.data.toString('hex')
    }));
    
    // Store the claim and its proof
    acc[claimKey] = {
      value: claimValue,
      salt: salt.toString(),
      proof
    };

    return acc;
  }, {});
  const numericProof = revealedClaims.numericalClaims?.reduce((acc, claimKey) => {
    const claimValue = claimsData.claims[claimKey.claim];
    var value = claimValue;
    if (typeof value === 'string')
      value = CommitmentUtils.getPedersenCommitment(stringToBigInt(value),BigInt(claimsData.salt),pedGenParams)
    else 
      value =CommitmentUtils.getPedersenCommitment(BigInt(Math.round(value)), BigInt(claimsData.salt),pedGenParams)
    const claimString=  PointFn.toHexString(value)
    const proof = tree.getProof(claimString).map(p => ({
      position: p.position,
      data: p.data.toString('hex')
    }));

    const size = BigInt(closestPowerOfTwo(claimKey.max))
    const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);
    const subResult = CommitmentUtils.getPedersenCommitment(BigInt(Math.round(claimValue))- BigInt(claimKey.min), BigInt(claimsData.salt)- BigInt(revealedClaims.salt), pedGenParams);
    const subResult2 = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.max)- BigInt(Math.round(claimValue)), BigInt(revealedClaims.salt)- BigInt(claimsData.salt), pedGenParams);
    const uncompr_proof = ProofFactory.computeBulletproof(BigInt(Math.round(claimValue)) - BigInt(claimKey.min),  BigInt(claimsData.salt)- BigInt(revealedClaims.salt),  subResult, genParams, 0n, size,  false);
    const uncompr_proof2 = ProofFactory.computeBulletproof(BigInt(claimKey.max)- BigInt(Math.round(claimValue)), BigInt(revealedClaims.salt)- BigInt(claimsData.salt),  subResult2, genParams, 0n, size,  false);
    const compr_proof = uncompr_proof.compressProof(genParams,false);
    const compr_proof2 = uncompr_proof2.compressProof(genParams,false);
    const proof_json = compr_proof.toJson(false, PointFn);
    const proof_json2 = compr_proof2.toJson(false, PointFn);


    // Store the claim and its proof
    acc[claimKey.claim] = {
      value: claimString,
      proof,
      numerical_proof_low: proof_json,
      numerical_proof_high: proof_json2,
      numerical_value_low:  PointFn.toHexString(subResult),
      numerical_value_high:  PointFn.toHexString(subResult2)
    };

    return acc;
  }, {});

  
  // Prepare the output object
  const output = {
    revealedClaims: [proofs,numericProof]
  };

  // Write the output to a JSON file
  const outputFilename = `revealedClaims_${claimsJsonFilePath.replace(/^.*[\\/]/, '')}`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Revealed claims and their proofs have been saved to ${outputFilename}`);
}


export default generateProofsForRevealedClaims;