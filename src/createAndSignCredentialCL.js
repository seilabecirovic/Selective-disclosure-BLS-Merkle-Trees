import { Command } from 'commander';
import createAndSignCredential from './createAndSignCredential.js';


// process options
const program = new Command();
program.requiredOption('--claims <claims>', 'Filepath for claims in JSON format');
program.requiredOption('--key <key>', 'Filepath for private key');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await createAndSignCredential(options.claims,options.key);
    } catch (err) {
        console.log(err);
    }
})();