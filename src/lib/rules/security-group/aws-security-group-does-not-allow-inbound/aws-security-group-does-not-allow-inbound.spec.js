'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const co = require('co');
const RealAWS = require('aws-sdk');
const rule = require('./aws-security-group-does-not-allow-inbound');
const debug = require('debug')('snitch/aws-security-group-does-not-allow-inbound.spec');

const instance = {
    "ingress":
        [{
            "cidr_blocks": ["10.0.0.0/16", "204.4.6.0/16"],
            "from_port": 9025,
            "protocol": "tcp",
            "security_groups": [],
            "self": false,
            "to_port": 9050
        }],
    "name": 'test-server'
};

const provider = {};

describe('aws-security-group-does-not-allow-inbound', function () {
    it("Returns success if inbound traffic on specific IP and port range defined in config are not allowed through via the security group", co.wrap(function* () {
        const context = {config: {cidr: '204.4.6.2/32', port: '9070-9090'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("Returns success for specific IP that is not allowed to be open to inbound traffic at all", co.wrap(function* () {
        const context = {config: {cidr: '204.5.6.2/32'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("Returns success when any CIDR in the security group is open to inbound traffic on a range of ports", co.wrap(function* () {
        const context = {config: {port: '9070-9090'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("Returns success when any CIDR in the security group is open to inbound traffic on a specific port", co.wrap(function* () {
        const context = {config: {port: '10902'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("Returns success when any CIDR in the security group is open to inbound traffic on a specific port (integer)", co.wrap(function* () {
        const context = {config: {port: 10902}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("Returns fail for a specific ip that is not allowed to be open to inbound traffic from a port range", co.wrap(function* () {
        const context = {config: {cidr: '204.4.6.2/32', port: '9032-9034'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));
    it("Returns fail for a specific ip that is not allowed to be open to inbound traffic at all", co.wrap(function* () {
        const context = {config: {cidr: '204.4.6.2/32'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));
    it("Returns fail when any CIDR in the security group is open to inbound traffic on a range of ports", co.wrap(function* () {
        const context = {config: {port: '9032-9034'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));
    it("Returns fail when any CIDR in the security group is open to inbound traffic on a specific port", co.wrap(function* () {
        const context = {config: {port: '9033'}, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {
        let badProvider = new AWSPromiseMock();
        badProvider.Service('EC2', 'describeSecurityGroups', {
            SecurityGroups: [
                {
                    GroupName: "test-group",
                    IpPermissions: [
                        {
                            IpRanges: [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ],
                            ToPort: 22
                        }
                    ]
                }
            ]
        });
        let badResult = await rule.livecheck({provider: badProvider});
        expect(badResult.valid).toBe('fail');

        let goodProvider = new AWSPromiseMock();
        goodProvider.Service('EC2', 'describeSecurityGroups', {
            SecurityGroups: [
                {
                    GroupName: "test-group",
                    IpPermissions: [
                        {
                            IpRanges: [
                                {
                                    "CidrIp": "0.0.0.0/0"
                                }
                            ],
                            ToPort: 1234
                        }
                    ]
                }
            ]
        });
        let goodResult = await rule.livecheck({provider: goodProvider});
        expect(goodResult.valid).toBe('success');
    });
});