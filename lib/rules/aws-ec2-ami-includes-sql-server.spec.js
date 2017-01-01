'use strict';
const fs = require('fs');
const AWS = require('aws-stub');
const chai = require('chai');
const rule = require('./aws-ec2-ami-includes-sql-server');
const _ = require('lodash');
const debug = require('debug')('tfrules/test/aws-ec2-ami-includes-sql-server');

require('mocha-generators').install();

const expect = chai.expect;

const TemplateImages = [
  {
    ImageId : 'ami-d89d28b8',
    ImageLocation : 'amazon/Windows_Server-2012-RTM-English-64Bit-SQL_2012_SP2_Standard-2016.12.14',
    Name : 'Windows_Server-2012-RTM-English-64Bit-SQL_2012_SP2_Standard-2016.12.14'
  },
  {
    ImageId : 'ami-d89d28b7',
    ImageLocation : 'amazon/Windows_Server-2012-RTM-English-64Bit-2016.12.14',
    Name : 'Windows_Server-2012-RTM-English-64Bit-2016.12.14'
  }
];


describe('aws-ec2-ami-includes-sql-server', function() {
  it("should return a valid = 'success' when SQL server is required in an AMI that has SQL Server", function *() {
    const instance = { ami : 'ami-d89d28b8' };
    const provider = AWS( 'EC2', 'describeImages', { Images : [  TemplateImages[ 0 ] ] } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' when SQL Server is required for an AMI that does not have SQL Server", function *() {
    const instance = { ami : 'ami-d89d28b7' };
    const provider = AWS( 'EC2', 'describeImages', { Images : [  TemplateImages[ 1 ] ] } );
    const context = { config : true, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
  it("should return a valid = 'success' when SQL server should not be included for an AMI that does not have SQL Server", function *() {
    const instance = { ami : 'ami-d89d28b7' };
    const provider = AWS( 'EC2', 'describeImages', { Images : [  TemplateImages[ 1 ] ] } );
    const context = { config : false, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('success');
  });
  it("should return a valid = 'fail' when SQL server should not be included and the AMI has SQL Server included", function *() {
    const instance = { ami : 'ami-d89d28b8' };
    const provider = AWS( 'EC2', 'describeImages', { Images : [  TemplateImages[ 0 ] ] } );
    const context = { config : false, instance, provider };
    const result = yield rule.validate( context );
    expect(result.valid).to.equal('fail');
  });
});

