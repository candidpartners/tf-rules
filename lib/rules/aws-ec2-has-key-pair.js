'use strict';
const debug = require('debug')('tfrules/ec2-has-key-pair');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2HasKeyPair = {};

EC2HasKeyPair.docs = {
  description: 'EC2 Instance must have a key defined',
  recommended: true
};

EC2HasKeyPair.liveCheck = false;

EC2HasKeyPair.schema = { type : 'boolean' };

EC2HasKeyPair.paths = {
  rdsInstance : 'aws_instance'
};

EC2HasKeyPair.validate = function *( context ) {
  // debug( '%O', context );

  let result = null;
  if( context.config == true) {
    // debug('Instance: %j', context.instance)
    if( context.instance.key_name ) {
      result = {
        valid : 'success'
      };
    } else {
      result = {
        valid : 'fail',
        message : context.instance.tags.ApplicationCode + '_' + context.instance.tags.Name + ' is not using a key'
      };
    }
  }
  return result;
};

module.exports = EC2HasKeyPair;

