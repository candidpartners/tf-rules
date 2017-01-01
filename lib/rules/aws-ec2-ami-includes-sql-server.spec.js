'use strict';
const fs = require('fs');
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
  it("should return a valid = 'success'", function *() {
    const instance = { ami : 'ami-d89d28b8' };

    const EC2 = function() {};
    EC2.prototype.describeImages = function(filters) {
      const describeImagesReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            let queryResult = { Images : _.filter( TemplateImages, { ImageId : filters.ImageIds[ 0 ] } ) };
            resolve( queryResult );
          });
        }
      };
      return describeImagesReturn;
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
    const instance = { ami : 'ami-d89d28b7' };

    const EC2 = function() {};
    EC2.prototype.describeImages = function(filters) {
      const describeImagesReturn = {
        promise : function() {
          return new Promise( function (resolve, reject) {
            let queryResult = { Images : _.filter( TemplateImages, { ImageId : filters.ImageIds[ 0 ] } ) };
            resolve( queryResult );
          });
        }
      };
      return describeImagesReturn;
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

