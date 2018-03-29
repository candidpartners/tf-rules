'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-ec2-uses-security-group');
const debug = require('debug')('snitch/aws-ec2-uses-security-group.spec');
const co = require('co');

const instance = {
  'security_groups' : ['sg-fc423485'],
  'vpc_security_group_ids' : ['sg-fbcd0182'],
  'tags' : {
    'ApplicationCode' : 'Test Server'
  }
};

describe('aws-ec2-uses-security-group', function() {
  it("Returns 'success' for string value in the config", co.wrap(function *() {
    const provider = {};
    const context = {config : 'sg-fc423485', instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns 'success' for array value in the config", co.wrap(function *() {
    const provider = {};
    const context = {config : ['sg-fc423485','sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns 'success' when the EC2 instance has one of the security groups", co.wrap(function *() {
    const provider = {};
    const context = {config : ['sg-fc423486','sg-fbcd0182'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns 'fail' when the EC2 instance is missing both security groups", co.wrap(function *() {
    const provider = {};
    const context = {config : ['sg-fc423486','sg-fbcd0183'], instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
});