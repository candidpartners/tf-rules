'use strict';
const AWS = require('aws-stub');
const co = require('co');
const rule = require('./aws-security-group-does-not-allow-outbound');
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-outbound.spec');

const instance = { "egress" :
  [{
    "cidr_blocks":["10.0.0.0/16","204.4.6.0/16"],
    "from_port":9025,
    "protocol":"tcp",
    "security_groups":[],
    "self":false,
    "to_port":9050
  }],
  "name" : 'test-server'
};

const provider = {}

describe('aws-security-group-does-not-allow-outbound', function() {
  it("Returns success for specific IP that is not allowed to be open to outbound traffic on a port range", co.wrap(function *() {
    const context = {config : {cidr : '204.4.6.2/32',port : '9070-9090'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success for specific IP that is not allowed to have outbound traffic at all", co.wrap(function *() {
    const context = {config : {cidr : '204.5.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when any CIDR block in the security group is open to outbound traffic on a range of ports", co.wrap(function *() {
    const context = {config : {port : '9070-9090'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when any CIDR block in the security group is open to outbound traffic on a specific port", co.wrap(function *() {
    const context = {config : {port : '10902'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when any CIDR block in the security group is open to outbound traffic on a specific port (integer)", co.wrap(function *() {
    const context = {config : {port : 10902}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns fail for a specific ip that is not allowed to be open to outbound traffic from a port range", co.wrap(function *() {
    const context = {config : {cidr : '204.4.6.2/32',port : '9032-9034'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail for a specific ip that is not allowed to be open to outbound traffic at all", co.wrap(function *() {
    const context = {config : {cidr : '204.4.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail when any CIDR in the security group is open to outbound traffic on a range of ports", co.wrap(function *() {
    const context = {config : {port : '9032-9034'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail when any CIDR in the security group is open to outbound traffic on a specific port", co.wrap(function *() {
    const context = {config : {port : '9033'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
});