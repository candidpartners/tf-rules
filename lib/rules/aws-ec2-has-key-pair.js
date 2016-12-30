'use strict';
const debug = require('debug')('tfrules/ec2-has-key-pair');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2HasKeyPair = {};

EC2HasKeyPair.docs = {
  description: 'EC2 Keypair must exist in the account and region',
  recommended: true
};

EC2HasKeyPair.liveCheck = true;

EC2HasKeyPair.schema = { type : 'boolean' };

EC2HasKeyPair.paths = {
  rdsInstance : 'aws_instance'
};

EC2HasKeyPair.validate = function *( context ) {
  // debug( '%O', context );

  const ec2 = new context.provider.EC2();
  let result = null;
  if( context.config == true ) {
    // debug('Instance: %j', context.instance)
    if( context.instance.key_name ) {
      const queryResult = yield ec2.describeKeyPairs({
        Filters : [
          {
            'Name': 'key-name',
            'Values': [context.instance.key_name]
          }
        ]
      }).promise();
      // const queryResult = yield ec2.describeKeyPairs({
      //   KeyNames : [context.instance.key_name]
      // }).promise();
      debug( 'Query Result: %O', queryResult );
      debug( 'Instance Key: %O', context.instance.key_name );
      if( queryResult.KeyPairs.length > 0 ) {
        result = {
          valid : 'success'
        };
      } else {
        result = {
          valid : 'fail',
          message : `Key [${context.instance.key_name}] not found`
        };
      }
    }
  }
  return result;
};

module.exports = EC2HasKeyPair;

