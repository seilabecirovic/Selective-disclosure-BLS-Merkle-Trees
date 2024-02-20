import { Command } from 'commander';
import generateAndSaveKeys from './generateAndSaveKeys.js';


// process options
const program = new Command();
program.requiredOption('--issuerName <issuerName>', 'Name of the issuer');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await generateAndSaveKeys(options.issuerName);
    } catch (err) {
        console.log(err);
    }
})();