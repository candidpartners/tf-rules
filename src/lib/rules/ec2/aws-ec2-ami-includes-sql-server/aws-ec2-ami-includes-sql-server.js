'use strict';
const debug = require('debug')('snitch/rule/ec2-ami-includes-sql-server');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2AMIIncludesSQL = {};

EC2AMIIncludesSQL.uuid = "22bce450-2452-485f-ae3b-e244f47792ce";
EC2AMIIncludesSQL.groupName = "EC2";
EC2AMIIncludesSQL.config_triggers = ["AWS::EC2::Instance"];
EC2AMIIncludesSQL.paths = {EC2AMIIncludesSQL: 'aws_instance'};
EC2AMIIncludesSQL.docs = {
  description: 'The AMI includes a MS SQL Server.',
  recommended: false
};
EC2AMIIncludesSQL.schema = { type : 'boolean' };


EC2AMIIncludesSQL.validate = function *( context ) {
  debug( '%s', context.instance.ami );

  const ec2 = new context.provider.EC2();
  let result = null;
  // debug('Instance: %j', context.instance)
  if( context.instance.ami ) {
    const queryResult = yield ec2.describeImages({
      ImageIds : [ context.instance.ami ]
    }).promise();
    debug( 'Instance AMI: %s', context.instance.ami );
    if( queryResult.Images.length > 0 ) {
      const image = queryResult.Images[ 0 ];
      debug( 'Image: %O', image );
      const foundSQL = image.Name.indexOf('-SQL_') > -1 && image.ImageLocation.indexOf('-SQL_') > -1;
      debug( 'foundSQL : %o', foundSQL );
      if( context.config == true && foundSQL == false ) {
        result = {
          valid : 'fail',
          message : `AMI ${context.instance.ami} does not include SQL and it should`
        };
      } else if ( context.config == false && foundSQL == true ) {
        result = {
          valid : 'fail',
          message : `AMI ${context.instance.ami} includes SQL and it should not`
        };
      } else {
        result = { valid : 'success' };
      }
    } else {
      result = {
        valid : 'fail',
        message : `AMI [${context.instance.ami}] not found`
      };
    }
  }
  debug( 'result : %o', result );
  return result;
};

module.exports = EC2AMIIncludesSQL;

