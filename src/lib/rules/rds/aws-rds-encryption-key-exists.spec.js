'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-rds-encryption-key-exists');
const co = require('co');

const Keys = [
  'whatever',
  'arn:fake:key:id',
  'something'
].map( KeyArn => ({ KeyArn }) );

describe('rds-encryption-key-exists', function() {
  it("should return a valid = 'success'", co.wrap(function *() {
    const instance = { kms_key_id : 'arn:fake:key:id' };
    const provider = AWS( 'KMS', 'listKeys', { Keys } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).toBe('success');
  }));
  it("should return a valid = 'fail'", co.wrap(function *() {
    const instance = { kms_key_id : 'arn:fake:key:id:not:exist' };
    const provider = AWS( 'KMS', 'listKeys', { Keys } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  }));
});

