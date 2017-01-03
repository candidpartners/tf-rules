'use strict';
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-instance-uses-security-group');
const debug = require('debug')('tfrules/aws-ec2-instance-uses-security-group.spec');

require('mocha-generators').install();

const expect = chai.expect;


describe('aws-ec2-instance-uses-security-group', function() {
  it("should return a valid = 'success' for string config", function *() {
    const instance = {
      'security_groups' : ['sg-fc423485'],
      'vpc_security_group_ids' : ['sg-fbcd0182'],
      'tags' : {
        'ApplicationCode' : 'Test Server'
      }
    };
    const provider = {};
    const context = {config : 'sg-fc423485', instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'success' for array config", function *() {
    const instance = {
      'security_groups' : ['sg-fc423485'],
      'vpc_security_group_ids' : ['sg-fbcd0182'],
      'tags' : {
        'ApplicationCode' : 'Test Server'
      }
    };
    const provider = {};
    const context = {config : ['sg-fc423485','sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail'", function *() {
    const instance = {
      'security_groups' : ['sg-fc423485'],
      'tags' : {
        'ApplicationCode' : 'Test Server'
      }
    };
    const provider = {};
    const context = {config : ['sg-fc423485,sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});