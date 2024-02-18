import _ from 'underscore';
import net from 'net';
import { SocksClient } from 'socks';
import url from 'url';
import parseRawData from './parseRawData.js';

import SERVERS from './servers.json' with { type: "json" };

const cleanParsingErrors = (string) => {
    return string.replace(/^[:\s]+/, '').replace(/^https?[:\/]+/, '') || string;
};

const lookup = async (addr, options = {}) => {
    return new Promise((resolve, reject) => {
        if (typeof options === 'function') {
            reject(new Error('Callback function not supported. Use async/await or Promises.'));
        }

        _.defaults(options, {
            follow: 2,
            timeout: 60000 // 60 seconds in ms
        });

        let { server, proxy, timeout } = options;

        if (!server) {
            switch (true) {
                case _.contains(addr, '@'):
                    reject(new Error('lookup: email addresses not supported'));
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
            reject(new Error('lookup: no whois server is known for this kind of object'));
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

            socket.on('close', async (err) => {
                if (options.follow > 0) {
                    const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server|refer):[^\S\n]*((?:r?whois|https?):\/\/)?([0-9A-Za-z\.\-_]*)/);
                    if (match && match[3] !== server.host) {
                        options.follow--;
                        options.server = cleanParsingErrors(match[3].trim());
                        await lookup(addr, options, (err, parts) => {
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
            }, async (err, { socket }) => {
                if (err) {
                    reject(err);
                    return;
                }
                if (timeout) {
                    socket.setTimeout(timeout);
                }
                _lookup(socket, (err, data) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    let result = {};
                    if ( typeof data === 'object' ) {
                        result = data.map(function(data) {
                            data.data = parseRawData(data.data);
                            return data;
                        });
                    } else {
                        result = parseRawData(data);
                    }
                    console.log(result)
                    resolve(result);
                });
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
            _lookup(socket, (err, data) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                let result = {};
                if ( typeof data === 'object' ) {
                    result = data.map(function(data) {
                        data.data = parseRawData(data.data);
                        return data;
                    });
                } else {
                    result = parseRawData(data);
                }
                resolve(result);
            });
        }
    });
};

export { lookup };
