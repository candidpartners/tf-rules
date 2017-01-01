'use strict';
const fs = require('fs');
const chai = require('chai');
const cli = require('./cli');
const _ = require('lodash');
const debug = require('debug')('tfrules/bin/test/cli');

require('mocha-generators').install();

const expect = chai.expect;

describe('CLI', function() {
  it("should load rules", function *() {
    yield cli.main({ plan : './test/data/plan.txt' });
    expect( cli.rules ).to.be.an('object');
    debug( 'Rules loaded %j', cli.rules );
  });
});

