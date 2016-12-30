'use strict';
const debug = require('debug')('tfrules/rds-encryption-exists');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RDSEncryptionKeyExists = {};

RDSEncryptionKeyExists.docs = {
  description: 'RDS using a KMS key must exist in the account and region',
  recommended: true
};

RDSEncryptionKeyExists.liveCheck = true;

RDSEncryptionKeyExists.schema = { type : 'boolean' };

RDSEncryptionKeyExists.paths = {
  rdsInstance : 'aws_db_instance'
};

RDSEncryptionKeyExists.validate = function *( context ) {
  // debug( '%O', context );
  const kms = new context.provider.KMS();
  let result = null;
  if( context.config == true ) {
    if( context.instance.kms_key_id ) {
      const queryResult = yield kms.listKeys( {} ).promise();
      debug( '%O', queryResult );
      debug( '%O', context.instance.kms_key_id );
      if( _.find( queryResult.Keys, { KeyArn : context.instance.kms_key_id } ) ) {
        result = {
          valid : 'success'
        };
      } else {
        result = {
          valid : 'fail',
          message : `Key [${context.instance.kms_key_id}] not found`
        };
      }
    }
  }
  return result;
};

module.exports = RDSEncryptionKeyExists;

