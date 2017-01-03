'use strict';
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-security-group-exists');
const debug = require('debug')('tfrules/aws-security-group-exists.spec');

require('mocha-generators').install();

const expect = chai.expect;


describe('aws-security-group-exists', function() {
  it("should return a valid = 'success' for security_groups and vpc_security_group_ids", function *() {
    const instance = {
      'security_groups' : ['sg-fc423485'],
      'vpc_security_group_ids' : ['sg-fbcd0182']
    };
    
    const SecurityGroups = {
      'SecurityGroups' : [
        {
          'GroupId' : 'sg-fc423485',
          'OwnerId' : '675443866135'
        },
        {
          'GroupId' : 'sg-fbcd0182',
          'OwnerId' : '675443866135'
        },
        {
          'GroupId' : 'sg-ecdc1073',
          'OwnerId' : '675443866135'
        },
      ]
    };
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : true, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' for security_groups", function *() {
    const instance = {
      'security_groups' : ['sg-fc423485'],
    };
    
    const SecurityGroups = {
      'SecurityGroups' : [
        {
          'GroupId' : 'sg-fbcd018',
          'OwnerId' : '675443866135'
        },
      ]
    };
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : true, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'fail' for vpc_security_group_ids", function *() {
    const instance = {
      'vpc_security_group_ids' : ['sg-fbcd0182']
    };
    
    const SecurityGroups = {
      'SecurityGroups' : [
        {
          'GroupId' : 'sg-fc423485',
          'OwnerId' : '675443866135'
        },
      ]
    };
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : true, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});