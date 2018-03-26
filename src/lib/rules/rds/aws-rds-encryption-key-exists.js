'use strict';
const debug = require('debug')('snitch/rds-encryption-exists');
const co = require('co');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RDSEncryptionKeyExists = {};

RDSEncryptionKeyExists.uuid = "196beb21-bb42-4a58-9ea0-0478c5f1042a";
RDSEncryptionKeyExists.groupName = "RDS";

RDSEncryptionKeyExists.docs = {
  description: 'RDS using a KMS key must exist in the account and region',
  recommended: true
};

RDSEncryptionKeyExists.schema = { type : 'boolean' };

RDSEncryptionKeyExists.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let rds = new provider.RDS();
    let reqTags = config;

    // Get all RDS instances
    let result = yield rds.describeDBInstances().promise();
    let DBInstances = result.DBInstances;

    while (result.NextToken) {
        let result = yield rds.describeDBInstances({NextToken: result.NextToken}).promise();
        DBInstances = [...DBInstances, ...result.DBInstances];
    }

    let Instances = _.flatMap(DBInstances);


    // Find unencrypted instances
    let UnencryptedInstances = Instances.filter(instance => instance.kms_key_id === undefined);

    if (UnencryptedInstances.length > 0) {
        let noncompliant_resources = UnencryptedInstances.map(inst => {
            return {
                id: inst.DBInstanceIdentifier,
                message: `${inst.DBInstanceIdentifier} instance unencrypted`
            }
        });
        return {
            valid: "fail",
            message: "One or more RDS instances are not encrypted.",
            noncompliant_resources
        }
    }
    else {
        return {valid: "success"}
    }
});

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

