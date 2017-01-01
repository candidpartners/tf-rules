'use strict';
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-rds-encryption-key-exists');
// const debug = require('debug')('tfrules/test/rds-encryption-exists');

require('mocha-generators').install();

const expect = chai.expect;

const Keys = [
  'whatever',
  'arn:fake:key:id',
  'something'
].map( KeyArn => ({ KeyArn }) );

describe('rds-encryption-key-exists', function() {
  it("should return a valid = 'success'", function *() {
    const instance = { kms_key_id : 'arn:fake:key:id' };
    const provider = AWS( 'KMS', 'listKeys', { Keys } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail'", function *() {
    const instance = { kms_key_id : 'arn:fake:key:id:not:exist' };
    const provider = AWS( 'KMS', 'listKeys', { Keys } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});

