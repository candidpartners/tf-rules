'use strict';
const fs = require('fs');
const chai = require('chai');
const rule = require('./aws-ec2-has-key-pair');
const _ = require('lodash');
const debug = require('debug')('tfrules/aws-ec2-has-key-pair');

require('mocha-generators').install();

const expect = chai.expect;


describe('aws-ec2-has-key-pair', function() {
  it("should return a valid = 'success'", function *() {
    const instance = {
      key_name : 'real-key-name'
    };
    
    const KeyPairs = [
      {
        'KeyName' : 'real-key-name',
        'KeyFingerprint' : 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
      },
      {
        'KeyName' : 'real-key-name2',
        'KeyFingerprint' : 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
      },
      {
        'KeyName' : 'wrong-key-name',
        'KeyFingerprint' : 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
      },
    ];
    
    const EC2 = function() {};
    EC2.prototype.describeKeyPairs = function(filters) {
      const listKeyPairsReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            let queryResult = {'KeyPairs' : _.filter(KeyPairs, {KeyName : filters.Filters[0].Values[0]})}
            resolve( queryResult );
          });
        }
      };
      return listKeyPairsReturn;
    };
    const provider = { EC2 };
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
      key_name : 'real-key-name'
    };
    
    const KeyPairs = [
      {
        'KeyName' : 'real-key-name2',
        'KeyFingerprint' : 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
      },
      {
        'KeyName' : 'wrong-key-name',
        'KeyFingerprint' : 'de:7e:e1:b2:24:51:11:bb:4d:8c:86:c7:da:e5:5b:3f'
      },
    ];
    
    const EC2 = function() {};
    EC2.prototype.describeKeyPairs = function(filters) {
      const listKeyPairsReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            let queryResult = {'KeyPairs' : _.filter(KeyPairs, {KeyName : filters.Filters[0].Values[0]})}
            resolve( queryResult );
          });
        }
      };
      return listKeyPairsReturn;
    };
    const provider = { EC2 };
    const context = {
      config : true,
      instance,
      provider
    };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});

