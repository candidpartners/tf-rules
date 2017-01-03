'use strict';
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-instance-uses-security-group');
const debug = require('debug')('tfrules/aws-ec2-instance-uses-security-group.spec');

require('mocha-generators').install();

const expect = chai.expect;

const instance = {
  'security_groups' : ['sg-fc423485'],
  'vpc_security_group_ids' : ['sg-fbcd0182'],
  'tags' : {
    'ApplicationCode' : 'Test Server'
  }
};

describe('aws-ec2-instance-uses-security-group', function() {
  it("Returns 'success' for string value in the config", function *() {
    const provider = {};
    const context = {config : 'sg-fc423485', instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns 'success' for array value in the config", function *() {
    const provider = {};
    const context = {config : ['sg-fc423485','sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("Returns 'fail' when the EC2 instance is missing the security group", function *() {
    const provider = {};
    const context = {config : ['sg-fc423485,sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});