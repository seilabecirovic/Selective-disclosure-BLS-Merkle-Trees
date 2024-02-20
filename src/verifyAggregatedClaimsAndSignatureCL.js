import { Command } from 'commander';
import aggregateClaimsAndSignatures from './aggregateClaimsAndSignatures.js';
import verifyAggregatedClaimsAndSignature from './verifyAggregatedClaimsAndSignature.js';

// process options
const program = new Command();
program.requiredOption('--claims <claims>', 'Filepath for aggregated claims');
program.requiredOption('--key <key...>', 'Filepaths for public keys');
program.requiredOption('--root <root...>', 'Filepaths for registered roots and signatures');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await verifyAggregatedClaimsAndSignature(options.claims,options.key,options.root);
    } catch (err) {
        console.log(err);
    }
})();
