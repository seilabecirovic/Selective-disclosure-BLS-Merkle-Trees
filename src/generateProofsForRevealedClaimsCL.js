import { Command } from 'commander';
import generateProofsForRevealedClaims from './generateProofsForRevealedClaims.js';

// process options
const program = new Command();
program.requiredOption('--claims <claims>', 'path to the claims');
program.requiredOption('--disclosed <disclosed>', 'path to the required claims');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await generateProofsForRevealedClaims(options.claims, options.disclosed);
    } catch (err) {
        console.log(err);
    }
})();