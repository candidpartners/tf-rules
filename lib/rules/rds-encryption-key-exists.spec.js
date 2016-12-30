'use strict';
const fs = require('fs');
const chai = require('chai');
const rule = require('./rds-encryption-key-exists');
const _ = require('lodash');
const debug = require('debug')('tfrules/rds-encryption-exists.spec');

require('mocha-generators').install();

const expect = chai.expect;


describe('rds-encryption-key-exists', function() {
  it("should return a valid = 'success'", function *() {
    const instance = {
      kms_key_id : 'arn:fake:key:id'
    };
    
    const Keys = [
      'whatever',
      'arn:fake:key:id',
      'something'
    ].map( KeyArn => ({ KeyArn }) );
    
    const KMS = function() {};
    KMS.prototype.listKeys = function() {
      const listKeysReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            resolve( { Keys } );
          });
        }
      };
      return listKeysReturn;
    };
    const provider = { KMS };
    const context = {
      config : true,
      instance,
      provider
    };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail'", function *() {
    const instance = {
      kms_key_id : 'arn:fake:key:id'
    };
    
    const Keys = [
      'whatever',
      'something'
    ].map( KeyArn => ({ KeyArn }) );
    
    const KMS = function() {};
    KMS.prototype.listKeys = function() {
      const listKeysReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            resolve( { Keys } );
          });
        }
      };
      return listKeysReturn;
    };
    const provider = { KMS };
    const context = {
      config : true,
      instance,
      provider
    };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});

