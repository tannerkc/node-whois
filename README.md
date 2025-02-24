# Node WHOIS

Node WHOIS is a WHOIS client for Node.js.

## Installation

```shell
    $ npm install whois-es6
```

#### Usage

```js
import { lookup } from 'whois-es6'
lookup('google.com', function(err, data) {
	console.log(data)
})
```

You may pass an object in between the address and the callback function to tweak the behavior of the lookup function:

```json
{
	"server":  "",   // this can be a string ("host:port") or an object with host and port as its keys; leaving it empty makes lookup rely on servers.json
	"follow":  2,    // number of times to follow redirects
	"timeout": 0,    // socket timeout, excluding this doesn't override any default timeout value
	"verbose": false // setting this to true returns an array of responses from all servers
	"bind": null     // bind the socket to a local IP address
	"proxy": {       // (optional) SOCKS Proxy
		"host": "",
		"port": 0,
		"type": 5    // or 4
	}
}
```

## Contributing

Contributions are welcome.

## License

Node WHOIS is available under the [BSD (2-Clause) License](http://opensource.org/licenses/BSD-2-Clause).

## Attribution

- [WHOIS](https://github.com/FurqanSoftware/node-whois): The original node WHOIS that this is based on
- [WHOIS-JSON](https://www.npmjs.com/package/whois-json): A wrapper for WHOIS that returns JSON data

This repo was started to fix punycode deprecation in WHOIS for a person project.
