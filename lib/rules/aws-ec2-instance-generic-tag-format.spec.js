'use strict';
const fs = require('fs');
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-instance-generic-tag-format');
const _ = require('lodash');
const debug = require('debug')('tfrules/generic-tag-format');

require('mocha-generators').install();

const expect = chai.expect;

const Tags = [
  {
    'TagOne' : 'ABC',
    'TagTwo': 'hello-world'
  },
  {
    'BadTag' : 'Hello! Bad tag ***'
  },
  {
    'MixedTag1' : 'ABC',
    'MixedTag2' : 'Hello! Bad tag ***'
  }
];

describe('aws-ec2-instance-generic-tag-format', function() {
  it("should return a valid = 'success' when the tag format is correct", function *() {
    const instance = { tags: Tags[0] };
    const context = { config : true, instance };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' when the tag format is invalid", function *() {
    const instance = { tags: Tags[1] };
    const context = { config : true, instance };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'fail' when the tag format is invalid, even with some valid tags", function *() {
    const instance = { tags: Tags[2] };
    const context = { config : true, instance };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'success' when the tag is invalid but rule is disabled", function *() {
    const instance = { tags: Tags[1] };
    const context = { config : false, instance };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
});
