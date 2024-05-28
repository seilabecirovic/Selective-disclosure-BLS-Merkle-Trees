import { Command } from 'commander';
import requiredClaims from './requiredClaims.js';
// process options
const program = new Command();
program.requiredOption('--name <name>', 'name of the verifier');
program.requiredOption('--disclose <disclose...>', 'required string claims');
program.requiredOption('--numerical <numerical...>', 'required numerical claims (proof)');
program.requiredOption('--min <min...>', 'required minimum value');
program.requiredOption('--max <max...>', 'required maximum value');
program.parse(process.argv);
const options = program.opts();

void (async () => {
    try {
        await requiredClaims(options.name, options.disclose, options.numerical,options.min,options.max);
    } catch (err) {
        console.log(err);
    }
})();

