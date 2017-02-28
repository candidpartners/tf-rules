'use strict';
const fs = require('fs');
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-instance-tag-format');
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

require('mocha-generators').install();

const expect = chai.expect;

const Tags = [
  {
    'TagOne' : 'ABC',
  },
  {
    'TagOne' : 'BAD_TAG',
  }
];

describe('aws-ec2-instance-tag-format', function() {
  it("should return a valid = 'success' when the tag exists and is valid", function *() {
    const instance = { tags: Tags[0] };
    const context = { config : [{
      'name' : 'TagOne',
      'format': '^[A-Z]{3}$'
    }], instance, planType: 'add' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' when the tag exists and is invalid", function *() {
    const instance = { tags: Tags[1] };
    const context = { config : [{
      'name' : 'TagOne',
      'format': '^[A-Z]{3}$'
    }], instance, planType: 'add' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'success' when the tag does not exist", function *() {
    const instance = { };
    const context = { config : [{
      'name' : 'TagOne',
      'format': '^[A-Z]{3}$'
    }], instance, planType: 'add' };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
});
