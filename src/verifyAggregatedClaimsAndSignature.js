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

async function verifyClaims(revealedClaims, rootSignatureFilePath, publicKeyFilePath,requiredClaimsFilePath) {
    // Initialize the BLS library
   
    var bls = await loadBls();
  
    // Read and parse the root and signature file
    const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));
    const requiredClaims  = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

    // Read and parse the public key file
    const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
    const publicKeyHex = publicKeyData.publicKey;
    const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex,'hex'));
   
    // Verify each claim
    const tree = new MerkleTree([], sha256, { sortPairs: true }); // Dummy tree for verification
    const isValidClaims =revealedClaims.every(claimGroup => {
      return Object.entries(claimGroup).every(([key, { value, salt, proof, numerical_proof_low,numerical_proof_high, numerical_value_low,numerical_value_high }]) => {
       var leaf = value;
      if (salt){
      if (typeof value === 'string')
        value = stringToBigInt(value)
      else 
        value = BigInt(value)
      leaf=  PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, BigInt(salt),pedGenParams))
      }
      const proofObjects = proof.map(p => ({ position: p.position, data: Buffer.from(p.data, 'hex') }));
      let validTree =  tree.verify(proofObjects, leaf, merkleRoot) 
      let validNumeric= true
      let validRangeLow= true
      let validRangeHigh = true
      if (numerical_proof_low){
        const claimKey = requiredClaims.numericalClaims.find(x=>x.claim===key)
        const size = BigInt(closestPowerOfTwo(claimKey.max))
        const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);  
        const proof_low = CompressedBulletproof.fromJsonString(
          numerical_proof_low, 
          genParams.pedGen.CurveFn, 
          PointFn
        );
        const proof_high = CompressedBulletproof.fromJsonString(
          numerical_proof_high, 
          genParams.pedGen.CurveFn, 
          PointFn
        );
  
  
        validRangeLow = proof_low.verify(0n, size, PointFn.fromHexString(numerical_value_low,genParams.pedGen.CurveFn), genParams)
  
        validRangeHigh = proof_high.verify(0n, size, PointFn.fromHexString(numerical_value_high,genParams.pedGen.CurveFn), genParams)
       const mini = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.min), BigInt(requiredClaims.salt), pedGenParams);
       const maxi = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.max), BigInt(requiredClaims.salt), pedGenParams);
  
        var sub= CommitmentUtils.comSubCom(PointFn.fromHexString(leaf,pedGenParams.CurveFn), mini, PointFn)
        var sub2= CommitmentUtils.comSubCom(maxi, PointFn.fromHexString(leaf,pedGenParams.CurveFn), PointFn)
        validNumeric=(PointFn.toHexString(sub)===numerical_value_low)&&(PointFn.toHexString(sub2)===numerical_value_high)
      }
       return validTree && validNumeric && validRangeLow && validRangeHigh
    });
    });
    // Verify the signature
    const isValidSignature = bls.AugSchemeMPL.verify(publicKey,
      merkleRoot,
      bls.G2Element.from_bytes(Buffer.from(signature, 'hex'))
    );
  
    return isValidClaims && isValidSignature
  }
  


async function verifyAggregatedClaimsAndSignature(aggregatedFilePath, publicKeyFiles, rootSignatureFiles,requiredClaimsFiles) {
    // Initialize the BLS library


    var bls = await loadBls();
    // Read the aggregated claims and signature
    const { aggregatedClaims, aggregatedSignature } = JSON.parse(fs.readFileSync(aggregatedFilePath, 'utf8'));
    const aggregatedSignatureBytes = Buffer.from(aggregatedSignature, 'hex');
    const aggregatedSignatures = bls.G2Element.from_bytes(aggregatedSignatureBytes)
    
    //Check each single validity
    for (let i = 0; i < rootSignatureFiles.length; i++) {
        const isValidClaim = await verifyClaims(aggregatedClaims[i],rootSignatureFiles[i], publicKeyFiles[i],requiredClaimsFiles[i]);
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