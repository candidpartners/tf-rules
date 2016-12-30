'use strict';
const fs = require('fs');
const chai = require('chai');
const rule = require('./rds-encryption-key-exists');
const _ = require('lodash');
const debug = require('debug')('tfrules/rds-encryption-exists.spec');

require('mocha-generators').install();

const expect = chai.expect;

const Keys = [
  'whatever',
  'arn:fake:key:id',
  'something'
].map( KeyArn => ({ KeyArn }) );

const KMS = function() {};
KMS.prototype.listKeys = function() { return {
  promise : function() {
    return new Promise( function (resolve, reject) {
      resolve( { Keys } );
    });
  }
}};

const provider = { KMS };

describe('rds-encryption-key-exists', function() {
  before(function() {
    debug('rds-encryption-key-exists.before');
    const instance = {
      kms_key_id : 'arn:fake:key:id'
    };
    this.context = {
      config : true,
      instance,
      provider,
      _
    };
  });
  it('should return a valid result', function *() {
    const result = yield rule.validate( this.context );
    expect(result.valid).to.equal('success');
  });
});

