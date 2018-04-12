'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-security-group-exists');
const co = require('co');
const debug = require('debug')('snitch/aws-security-group-exists.spec');

const SecurityGroups = {
  'SecurityGroups' : [
    {'GroupId' : 'sg-fc423485','OwnerId' : '675443866135'},
    {'GroupId' : 'sg-fbcd0182','OwnerId' : '675443866135'},
    {'GroupId' : 'sg-ecdc1073','OwnerId' : '675443866135'},
  ]
};

describe('aws-security-group-exists', function() {
  it("Returns 'success' for classic security groups and vpc security groups", co.wrap(function *() {
    const instance = {'security_groups' : ['sg-fc423485'],'vpc_security_group_ids' : ['sg-fbcd0182']};
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : {enabled: true}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("Returns fail when classic security groups defined in the config are missing from the instance", co.wrap(function *() {
    const instance = {'security_groups' : ['sg-fc534596'],};
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : {enabled: true}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
  it("Returns fail when vpc security groups defined in config are missing from instances", co.wrap(function *() {
    const instance = {'vpc_security_group_ids' : ['sg-fbcd1293']};
    const provider = AWS('EC2', 'describeSecurityGroups', SecurityGroups);
    const context = {config : {enabled: true}, instance, provider};
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
});