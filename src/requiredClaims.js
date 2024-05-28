import fs  from 'fs';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js'
const library = "elliptic"
const curveName = "secp256k1";
const Rand = bulletproofs.Rand;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);

async function requiredClaims(name, disclosedClaims, numericalClaims, minValues, maxValues) {
    // Check if the lengths of numericalClaims, minValues, and maxValues match
    if (numericalClaims.length !== minValues.length || numericalClaims.length !== maxValues.length) {
        console.error('Length of numerical claims, min values, and max values must be the same');
        return;
    }
    const salt = Rand.randUnder(pedGenParams.n);

    // Create the object with the given parameters
    const data = {
        name: name,
        disclosedClaims: disclosedClaims,
        numericalClaims: numericalClaims.map((claim, index) => ({
            claim: claim,
            min: minValues[index],
            max: maxValues[index]
        })),
        salt: salt.toString()  // Convert BigInt to string for JSON serialization
    };

    // Convert the object to a JSON string
    const jsonData = JSON.stringify(data, null, 2);

    // Write the JSON string to the file
    fs.writeFile(`${name}RequiredDisclosures.json`, jsonData, 'utf8', (err) => {
        if (err) {
            console.error('Error writing to file', err);
        } else {
            console.log('JSON file has been saved.');
        }
    });
}

export default requiredClaims;