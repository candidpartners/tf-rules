'use strict';
const debug = require('debug')('snitch/ec2-uses-key-pair');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2UsesKeyPair = {};

EC2UsesKeyPair.uuid = "2812b528-8cfd-4d31-84f8-da61177ddd9c";
EC2UsesKeyPair.groupName = "EC2";

EC2UsesKeyPair.docs = {
  description: 'EC2 Instance must use the specified key',
  recommended: true
};

EC2UsesKeyPair.schema = { type : 'string' };

EC2UsesKeyPair.paths = {
  rdsInstance : 'aws_instance'
};

EC2UsesKeyPair.validate = function *( context ) {
  // debug( '%O', context );

  let result = null;
  if( context.config ) {
    // debug('Instance: %j', context.instance)
    if( context.instance.key_name == context.config ) {
      result = {
        valid : 'success'
      };
    } else {
      result = {
        valid : 'fail',
        message : context.instance.tags.ApplicationCode + '_' + context.instance.tags.Name + ' is not using the key "' + context.config + '"'
      };
    }
  }
  return result;
};

module.exports = EC2UsesKeyPair;

