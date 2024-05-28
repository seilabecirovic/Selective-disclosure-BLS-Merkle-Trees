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

async function verifyClaims(proofsFilePath, rootSignatureFilePath, publicKeyFilePath, requiredClaimsFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read and parse the proofs file
  const { revealedClaims } = JSON.parse(fs.readFileSync(proofsFilePath, 'utf8'));
  const requiredClaims  = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

  // Read and parse the root and signature file
  const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));

  // Read and parse the public key file
  const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
  const publicKeyHex = publicKeyData.publicKey;
  const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex,'hex'));
 
  // Verify each claim
  const tree = new MerkleTree([], sha256, { sortPairs: true }); // Dummy tree for verification

  const isValidClaims =revealedClaims.every(claimGroup => {
    return Object.entries(claimGroup).every(([key, { value, salt, proof, numerical_proof, numerical_value }]) => {
     var leaf = value;
    if (salt){
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value =  BigInt(Math.round(value));
    leaf=  PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, BigInt(salt),pedGenParams))
    }
    const proofObjects = proof.map(p => ({ position: p.position, data: Buffer.from(p.data, 'hex') }));
    let validTree =  tree.verify(proofObjects, leaf, merkleRoot) 
    let validNumeric= true;
    let validRange = true
    if (numerical_proof){
      const claimKey = requiredClaims.numericalClaims.find(x=>x.claim===key)
      const size = BigInt(closestPowerOfTwo(claimKey.max-claimKey.min))
      const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);  
      const proof2 = CompressedBulletproof.fromJsonString(
        numerical_proof, 
        genParams.pedGen.CurveFn, 
        PointFn
      );

     validRange = proof2.verify(0n, size, PointFn.fromHexString(numerical_value,genParams.pedGen.CurveFn), genParams)
     const godine = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.min), BigInt(requiredClaims.salt), pedGenParams);
      var sub= CommitmentUtils.comSubCom(PointFn.fromHexString(leaf,pedGenParams.CurveFn), godine, PointFn)
      
      validNumeric=PointFn.toHexString(sub)===numerical_value
    }
     return validTree && validNumeric && validRange
  });
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