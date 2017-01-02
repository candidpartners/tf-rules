'use strict';
const fs = require('fs');
const chai = require('chai');
const cli = require('./cli');
const _ = require('lodash');
const debug = require('debug')('tfrules/bin/test/cli');

require('mocha-generators').install();

const expect = chai.expect;

describe('CLI', function() {
  before(function *() {
    yield cli.main({ plan : './test/data/plan.txt', dryRun : true });
    debug( 'Rules loaded %O', cli.rules );
    debug( 'Config %O', cli.config );
  });  
  it("should load rules as an object", function () {
    expect( cli.rules ).to.be.an('object');
  });
  it("should load rule configurations as an array", function *() {
    expect( cli.config ).to.be.an('array');
  });
  it("should load custom rule configuration aws-ec2-uses-key-pair", function *() {
    const config = _.find( cli.config, { 'aws-ec2-uses-key-pair': 'MyKey' } );
    expect(config).to.not.be.null;
  });
});

