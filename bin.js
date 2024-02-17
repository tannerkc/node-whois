import yargs from 'yargs';
import * as whois from './index';
import util from 'util';

const argv = yargs
    .usage('$0 [options] address')
    .default('s', null)
    .alias('s', 'server')
    .describe('s', 'whois server')
    .default('f', 0)
    .alias('f', 'follow')
    .describe('f', 'number of times to follow redirects')
    .default('p', null)
    .alias('p', 'proxy')
    .describe('p', 'SOCKS proxy')
    .boolean('v')
    .default('v', false)
    .alias('v', 'verbose')
    .describe('v', 'show verbose results')
    .default('b', null)
    .alias('b', 'bind')
    .describe('b', 'bind to a local IP address')
    .boolean('h')
    .default('h', false)
    .alias('h', 'help')
    .describe('h', 'display this help message')
    .argv;

if (argv.h) {
    yargs.showHelp();
    process.exit(0);
}

if (!argv._[0]) {
    yargs.showHelp();
    process.exit(1);
}

whois.lookup(argv._[0], {
    server: argv.server,
    follow: argv.follow,
    proxy: argv.proxy,
    verbose: argv.verbose,
    bind: argv.bind
}, (err, data) => {
    if (err) {
        console.log(err);
        process.exit(1);
    }

    if (util.isArray(data)) {
        for (const part of data) {
            if (typeof part.server === 'object') {
                console.log(part.server.host);
            } else {
                console.log(part.server);
            }
            console.log(part.data);
            console.log();
        }
    } else {
        console.log(data);
    }
});
