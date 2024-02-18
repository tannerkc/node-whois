import assert from 'assert';
import * as whois from './index.js';

describe('#lookup()', () => {
    it('should work with google.com', async () => {
        try {
            const data = await whois.lookup('google.com');
            assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
        } catch (error) {
            console.error(error)
            assert.fail(error);
        }
    });

    it('should work with 50.116.8.109', async () => {
        try {
            const data = await whois.lookup('50.116.8.109');
            assert.notEqual(data.toLowerCase().indexOf('netname:        linode-us'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });

    it('should work with 2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d', async () => {
        try {
            const data = await whois.lookup('2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d');
        } catch (error) {
            assert.fail(error);
        }
    });

    it('should honor specified WHOIS server', async () => {
        try {
            const data = await whois.lookup('gandi.net', { server: 'whois.gandi.net' });
            assert.notEqual(data.toLowerCase().indexOf('whois server: whois.gandi.net'), -1);
            assert.notEqual(data.toLowerCase().indexOf('domain name: gandi.net'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });

    it('should honor specified WHOIS server with port override', async () => {
        try {
            const data = await whois.lookup('tucows.com', { server: 'whois.tucows.com:43' });
            assert.notEqual(data.toLowerCase().indexOf('whois server: whois.tucows.com'), -1);
            assert.notEqual(data.toLowerCase().indexOf('domain name: tucows.com'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should follow specified number of redirects for domain', async () => {
        try {
            const data = await whois.lookup('google.com', { follow: 1 });
            assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should follow specified number of redirects for IP address', async () => {
        try {
            const data = await whois.lookup('176.58.115.202', { follow: 1 });
            assert.notEqual(data.toLowerCase().indexOf('inetnum:        176.58.112.0 - 176.58.119.255'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with verbose option', async () => {
        try {
            const data = await whois.lookup('google.com', { verbose: true });
            assert.equal((data[0].server == 'whois.verisign-grs.com') || (data[0].server == 'whois.markmonitor.com'), 1);
            assert.notEqual(data[0].data.toLowerCase().indexOf('domain name: google.com'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });    

    it('should work with nic.sh', async () => {
        try {
            const data = await whois.lookup('nic.sh');
            assert.notEqual(data.toLowerCase().indexOf('registry domain id: dede5cd207a640ae8285d181431a00c4-donuts'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with nic.io', async () => {
        try {
            const data = await whois.lookup('nic.io');
            assert.notEqual(data.toLowerCase().indexOf('registry domain id: 09b2461d0b6449ffbc9edb53bc7326c1-donuts'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with nic.ac', async () => {
        try {
            const data = await whois.lookup('nic.ac');
            assert.notEqual(data.toLowerCase().indexOf('registry domain id: bcb94de2bd4e43459a9ef5e67e2e02d3-donuts'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with nic.tm', async () => {
        try {
            const data = await whois.lookup('nic.tm');
            assert.notEqual(data.toLowerCase().indexOf('status : permanent/reserved'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with nic.global', async () => {
        try {
            const data = await whois.lookup('nic.global');
            assert.notEqual(data.toLowerCase().indexOf('registry domain id: 696c235291444e9ab8c0f1336238c349-donuts'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });    

    it('should work with srs.net.nz', async () => {
        try {
            const data = await whois.lookup('srs.net.nz');
            assert.notEqual(data.toLowerCase().indexOf('domain name: srs.net.nz'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with redundant follow', async () => {
        try {
            const data = await whois.lookup('google.com', { follow: 5 });
            assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with küche.de', async () => {
        try {
            const data = await whois.lookup('küche.de');
            assert.notEqual(data.toLowerCase().indexOf('domain: küche.de'), -1);
            assert.notEqual(data.toLowerCase().indexOf('status: connect'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with google.co.jp in english', async () => {
        try {
            const data = await whois.lookup('google.co.jp');
            assert.notEqual(data.toLowerCase().indexOf('a. [domain name]                google.co.jp'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
    it('should work with registry.pro', async () => {
        try {
            const data = await whois.lookup('registry.pro', { follow: 0 });
            assert.notEqual(data.toLowerCase().indexOf('domain id: a78bed915c9748fdbdf91224299d2058-donuts'), -1);
        } catch (error) {
            assert.fail(error);
        }
    });
    
});
