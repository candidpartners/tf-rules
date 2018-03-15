'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-security-group-allows-inbound');
const debug = require('debug')('snitch/aws-security-group-allows-inbound.spec');
const co = require('co');

let instance = { "ingress" : [{"cidr_blocks":["10.0.0.0/16","204.4.6.0/16"],"from_port":9025,"to_port":9050}],"name" : 'test-server'}

const provider = {}

describe('aws-security-group-allows-inbound', function() {
  it("Returns success for specific IP that is allowed to be open to inbound traffic on a port range", co.wrap(function *() {
    const context = {config : {cidr : '204.4.6.2/32',port : '9030-9040'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success for specific IP that is allowed to be open to all inbound traffic", co.wrap(function *() {
    let instance = { "ingress" : [{"cidr_blocks":["0.0.0.0/0","204.4.6.0/16"],"from_port":0,"to_port":0}],"name" : 'test-server'}    
    const context = {config : {cidr : '204.4.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when Returns success when there is a CIDR block of '0.0.0.0/0' in the security group that is open to inbound traffic on a range of ports", co.wrap(function *() {
    instance = { "ingress" : [{"cidr_blocks":["0.0.0.0/0","204.4.6.0/16"],"from_port":9030,"to_port":9050}],"name" : 'test-server'}    
    const context = {config : {port : '9030-9040'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when there is a CIDR block in the security group of 0.0.0.0/0 that is open to inbound traffic on a specific port", co.wrap(function *() {
    instance = { "ingress" : [{"cidr_blocks":["0.0.0.0/0","204.4.6.0/16"],"from_port":9030,"to_port":9050}],"name" : 'test-server'}    
    const context = {config : {port : '9045'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns success when there is a CIDR block in the security group of 0.0.0.0/0 that is open to inbound traffic on a specific port (integer)", co.wrap(function *() {
    instance = { "ingress" : [{"cidr_blocks":["0.0.0.0/0","204.4.6.0/16"],"from_port":9030,"to_port":9050}],"name" : 'test-server'}    
    const context = {config : {port : 9045}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns fail for a specific ip that is not allowed to be open to inbound traffic from a port range", co.wrap(function *() {
    instance = { "ingress" : [{"cidr_blocks":["10.0.0.0/16","204.4.6.0/16"],"from_port":9025,"to_port":9050}],"name" : 'test-server'}
    const context = {config : {cidr : '204.4.6.2/32',port : '9070-9080'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail for a specific ip that is not allowed to be open to any inbound traffic", co.wrap(function *() {
    const context = {config : {cidr : '204.4.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail when there isn't a CIDR block in the security group of 0.0.0.0/0 that is open to inbound traffic on a range of ports", co.wrap(function *() {
    const context = {config : {port : '9070-9080'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail when there isn't a CIDR block in the security group of 0.0.0.0/0 that is open to inbound traffic on a specific port", co.wrap(function *() {
    const context = {config : {port : '9090'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
});