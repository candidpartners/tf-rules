'use strict';
const fs = require('fs');
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-instance-tag-exists');
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-exists');

require('mocha-generators').install();

const expect = chai.expect;

const Tags = [
  {
    'TagOne' : 'ABC',
    'TagTwo': 'hello-world'
  },
  {
    'TagOne' : 'ABC'
  }
];

describe('aws-ec2-instance-tag-exists', function() {
  it("should return a valid = 'success' when the tag exists for non-modify plan type", function *() {
    const instance = { tags: Tags[0] };
    const context = { config : ['TagOne', 'TagTwo'], instance, planType: 'add' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' when the tag does not exist for non-modify plan type", function *() {
    const instance = { tags: Tags[1] };
    const context = { config : ['TagOne', 'TagTwo'], instance, planType: 'add' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'success' when the tag exists for modify plan type", function *() {
    const instance = { tags: Tags[0] };
    const context = { config : ['TagOne', 'TagTwo'], instance, planType: 'modify' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'success' when the tag does not exist for modify plan type", function *() {
    const instance = { tags: Tags[1] };
    const context = { config : ['TagOne', 'TagTwo'], instance, planType: 'modify' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
});
