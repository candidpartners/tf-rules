'use strict';
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-security-group-does-not-allow-inbound');
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-inbound.spec');

require('mocha-generators').install();

const expect = chai.expect;

const instance = { "ingress" : 
  [{
    "cidr_blocks":["10.0.0.0/16","204.4.6.0/16"],
    "from_port":9025,
    "protocol":"tcp",
    "security_groups":[],
    "self":false,
    "to_port":9050
  }],
  "name" : 'test-server'
}

// const instance2 = { "ingress" :
//   [{
//     "cidr_blocks":["192.168.1.254/16","204.4.6.0/16"],
//     "from_port":8050,
//     "protocol":"tcp",
//     "security_groups":[],
//     "self":false,
//     "to_port":9030
//   }]
// };
const provider = {}


describe('aws-security-group-exists', function() {
  it("Returns success for specific IP that is not allowed to have inbound traffic on a port range", function *() {
    const context = {config : {cidr : '204.4.6.2/32',port : '9070-9090'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns success for specific IP that is not allowed to have inbound traffic at all", function *() {
    const context = {config : {cidr : '204.5.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns success when any CIDR in the security group is listening on a range of ports", function *() {
    const context = {config : {port : '9070-9090'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns success when any CIDR in the security group is listening on a specific port", function *() {
    const context = {config : {port : '10902'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns fail for a specific ip that is not allowed to have inbound traffic from a port range", function *() {
    const context = {config : {cidr : '204.4.6.2/32',port : '9032-9034'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("Returns fail for a specific ip that is not allowed to have inbound traffic at all", function *() {
    const context = {config : {cidr : '204.4.6.2/32'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("Returns fail when any CIDR in the security group is listening on a range of ports", function *() {
    const context = {config : {port : '9032-9034'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("Returns fail when any CIDR in the security group is listening on a specific port", function *() {
    const context = {config : {port : '9033'}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});