'use strict';
const fs = require('fs');
const chai = require('chai');
const rule = require('./aws-ec2-uses-key-pair');
const _ = require('lodash');
const debug = require('debug')('tfrules/aws-ec2-uses-key-pair');

require('mocha-generators').install();

const expect = chai.expect;


describe('aws-ec2-has-key-pair', function() {
  it("should return a valid = 'success'", function *() {
    const instance = {
      key_name : 'real-key-name',
      tags: {
        ApplicationCode : 'TST',
        Name : 'TestInstance'
      }
    };
    
    const provider = { };
    const context = {
      config : 'real-key-name',
      instance,
      provider
    };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail'", function *() {
    const instance = { 
      tags: {
        ApplicationCode : 'TST',
        Name : 'TestInstance'
      } 
    };

    const provider = { };
    const context = {
      config : 'real-key-name',
      instance,
      provider
    };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});