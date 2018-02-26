'use strict';
const AWS = require('aws-stub');
const rule = require('./aws-rds-encryption-key-exists');

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
    expect(result.valid).toBe('success');
  });
  it("should return a valid = 'fail'", function *() {
    const instance = { kms_key_id : 'arn:fake:key:id:not:exist' };
    const provider = AWS( 'KMS', 'listKeys', { Keys } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).toBe('fail');
  });
});

