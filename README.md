# Selective-disclosure-BLS-Merkle-Trees
Proof of concept for selective disclosure of digital credentials using Merkle trees and BLS signatures. Main focus is on selective disclosure of claims in multiple credentials and their verification.


## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/seilabecirovic/Selective-disclosure-BLS-Merkle-Trees.git

cd Selective-disclosure-BLS-Merkle-Trees
```

2. Install required packages
```
npm install
```


## Usage

This section describes the command-line interface functionality of the library; corresponding functions can also be accessed through the API.

### Generate issuer keys

To generate an issuer signing key pair, run

```
npm run generate-keys -- --issuerName <issuerName>
```

where `issuerName` is the name of the issue. This function generates private and public keys and stores them in separate files.

### Sign a set of claims and record the root hash and signature

To create a Merkle tree from a set of claims and generate a signature on the root, run 

```
npm run create-credential -- --claims <claims> --key <key>
```

where `claims` is the path to the JSON file containing claims, while `key` is the path to the public key. This function generates a file which contains issuer, root hash and signature. 

### Selective disclosure of claims

To selectively disclose some claims, run

```
 npm run disclose-claims -- --claims <claims> --disclosed <disclosed...>
```

where `claims` is the path to the JSON claims file, `disclosed...` are a series of space-separated claim names to disclose. Function creates a file containing generated claims and Merkle tree proofs. 

### Verification of disclosed claims

To verify disclosed claims, run

```
npm run verify-single -- --proof <proof> --signature <signature> --key <key>
```

where 
`proof` is the path to the disclosed claims and proofs, `signature` is the path to the record file containing root hash and signature of credential, `key` is the path to the public key of issuer. Function verifies disclosed claims through root and through signature. 

### Selective disclosure of claims in multiple credentials

To selectively disclose claims from multiple credentials and generate a presentation, run

```
npm run create-presentation -- --claims <claims...> --roots <roots...>
```

where `claims` are paths to selectively disclosed claims and their proofs seperated by space, `roots...` are a series of space-separated paths to files containing hashes of roots and signatures of disclosed credentials. Function creates a file containing aggregated generated claims and Merkle tree proofs, alongside aggregated signature. 

### Verification of disclosed claims from multiple credentials

To verify disclosed claims, run

```
npm run verify-multiple -- --claims <claims> --key <key...> --root <root...>
```

where 
`proof` is the path to the aggregated disclosed claims and proofs, `key` is the path to the public keys of issuers separated by space and `root` are the space-separated filepaths of root hashes and signature for each credential. Function verifies disclosed claims of multiple credentials. 


## Example

The following steps give an end-to-end example on how to use the library, using test data.

1. Issuers A and B create their signing key pair (of default ES256 algorithm type)

```
npm run generate-keys --  --issuerName IssuerA

npm run generate-keys --  --issuerName IssuerB
```

2. Issuer A issues a credential, as well as issuer B

```
npm run create-credential -- --claims ./examples/claimsA.json --key IssuerA_privateKey.json

npm run create-credential -- --claims ./examples/claimsB.json --key IssuerB_privateKey.json 
```

3. Holder selectively disclose some claims from credential of issuer A and some claims from issuer B

```
npm run disclose-claims -- --claims ./examples/claimsA.json --disclosed given_name family_name

npm run disclose-claims -- --claims ./examples/claimsB.json --disclosed university
```

4. Verifier verifies the disclosed claims of both issuers seperately

```
npm run verify-single -- --proof revealedClaims_claimsA.json --signature IssuerA_claimsA_signature.json --key IssuerA_publicKey.json

npm run verify-single -- --proof revealedClaims_claimsB.json --signature IssuerB_claimsB_signature.json --key IssuerB_publicKey.json
```

5. Holder combines disclosed claims from issuer A and issuer B

```
npm run create-presentation -- --claims revealedClaims_claimsA.json revealedClaims_claimsB.json  --roots IssuerA_claimsA_signature.json IssuerB_claimsB_signature.json 
```

6. Verifier verifies aggregated presentation

```
 npm run verify-multiple -- --claims aggregatedClaimsAndSignatures.json --key IssuerA_publicKey.json IssuerB_publicKey.json --root IssuerA_claimsA_signature.json IssuerB_claimsB_signature.json 
```
