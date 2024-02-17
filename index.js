import _ from 'underscore';
import net from 'net';
import { SocksClient } from 'socks';
import url from 'url';

import SERVERS from './servers.json' with { type: "json" };

const cleanParsingErrors = (string) => {
    return string.replace(/^[:\s]+/, '').replace(/^https?[:\/]+/, '') || string;
};

const lookup = (addr, options = {}, done) => {
    if (typeof options === 'function') {
        done = options;
        options = {};
    }

    _.defaults(options, {
        follow: 2,
        timeout: 60000 // 60 seconds in ms
    });

    done = _.once(done);

    let { server, proxy, timeout } = options;

    if (!server) {
        switch (true) {
            case _.contains(addr, '@'):
                done(new Error('lookup: email addresses not supported'));
                return;
            case net.isIP(addr) !== 0:
                server = SERVERS['_']['ip'];
                break;
            default:
                let tld = url.domainToASCII(addr);
                while (true) {
                    server = SERVERS[tld];
                    if (!tld || server) break;
                    tld = tld.replace(/^.+?(\.|$)/, '');
                }
        }
    }

    if (!server) {
        done(new Error('lookup: no whois server is known for this kind of object'));
        return;
    }

    if (typeof server === 'string') {
        const [host, port] = server.split(':');
        server = { host, port };
    }

    if (typeof proxy === 'string') {
        const [ipaddress, port] = proxy.split(':');
        proxy = { ipaddress, port: parseInt(port) };
    }

    _.defaults(server, {
        port: 43,
        query: '$addr\r\n'
    });

    if (proxy) {
        _.defaults(proxy, {
            type: 5
        });
    }

    const _lookup = (socket, done) => {
        let idn = addr;
        if (server.punycode !== false && options.punycode !== false) {
            idn = url.domainToASCII(addr);
        }
        if (options.encoding) {
            socket.setEncoding(options.encoding);
        }
        socket.write(server.query.replace('$addr', idn));

        let data = '';
        socket.on('data', (chunk) => {
            data += chunk;
        });

        socket.on('timeout', () => {
            socket.destroy();
            done(new Error('lookup: timeout'));
        });

        socket.on('error', (err) => {
            done(err);
        });

        socket.on('close', (err) => {
            if (options.follow > 0) {
                const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server|refer):[^\S\n]*((?:r?whois|https?):\/\/)?([0-9A-Za-z\.\-_]*)/);
                if (match && match[3] !== server.host) {
                    options.follow--;
                    options.server = cleanParsingErrors(match[3].trim());
                    lookup(addr, options, (err, parts) => {
                        if (err) {
                            return done(err);
                        }
                        if (options.verbose) {
                            done(null, [{ server: (typeof server === 'object') ? server.host.trim() : server.trim(), data }].concat(parts));
                        } else {
                            done(null, parts);
                        }
                    });
                    return;
                }
            }

            if (options.verbose) {
                done(null, [{ server: (typeof server === 'object') ? server.host.trim() : server.trim(), data }]);
            } else {
                done(null, data);
            }
        });
    };

    if (!Number.isInteger(server.port)) {
        server.port = 43;
    }

    if (proxy) {
        SocksClient.createConnection({
            proxy,
            destination: {
                host: server.host,
                port: server.port
            },
            command: 'connect',
            timeout
        }, (err, { socket }) => {
            if (err) {
                return done(err);
            }
            if (timeout) {
                socket.setTimeout(timeout);
            }
            _lookup(socket, done);
            socket.resume();
        });
    } else {
        const sockOpts = {
            host: server.host,
            port: server.port
        };
        if (options.bind) {
            sockOpts.localAddress = options.bind;
        }
        const socket = net.connect(sockOpts);
        if (timeout) {
            socket.setTimeout(timeout);
        }
        _lookup(socket, done);
    }
};

export { lookup };
