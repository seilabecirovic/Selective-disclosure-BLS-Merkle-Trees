import { Command } from 'commander';
import verifyClaims from './verifyClaims.js';

// process options
const program = new Command();
program.requiredOption('--proof <proof>', 'path to the disclosed claims and proof');
program.requiredOption('--signature <signature>', 'path to the signature');
program.requiredOption('--key <key>', 'path to the public key');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await verifyClaims(options.proof, options.signature, options.key);
    } catch (err) {
        console.log(err);
    }
})();

