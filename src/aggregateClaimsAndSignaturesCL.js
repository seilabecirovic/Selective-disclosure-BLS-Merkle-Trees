import { Command } from 'commander';
import aggregateClaimsAndSignatures from './aggregateClaimsAndSignatures.js';

// process options
const program = new Command();
program.requiredOption('--claims <claims...>', 'Filepath for disclosed claims');
program.requiredOption('--roots <roots...>', 'Filepaths for registered roots and signatures');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await aggregateClaimsAndSignatures(options.claims,options.roots);
    } catch (err) {
        console.log(err);
    }
})();

