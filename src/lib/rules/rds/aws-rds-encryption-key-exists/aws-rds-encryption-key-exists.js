// @flow
'use strict';
const debug = require('debug')('snitch/rds-encryption-exists');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RDSEncryptionKeyExists = {};

RDSEncryptionKeyExists.uuid = "196beb21-bb42-4a58-9ea0-0478c5f1042a";
RDSEncryptionKeyExists.groupName = "RDS";
RDSEncryptionKeyExists.tags = [["Candid", "1.0", "11"]];
RDSEncryptionKeyExists.config_triggers = ["AWS::RDS::DBInstance"];
RDSEncryptionKeyExists.paths = {RDSEncryptionKeyExists: "aws_db_instance"};
RDSEncryptionKeyExists.docs = {
    description: 'All RDS instances are encrypted using KMS keys.',
    recommended: true
};
RDSEncryptionKeyExists.schema = {
    type: 'object',
    properties: {
        exclude: {
            type: "array",
            items: {
                type: "string"
            }
        }
    }
};

RDSEncryptionKeyExists.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let rds = new provider.RDS();

    // Get all RDS instances
    let result = await rds.describeDBInstances().promise();
    let DBInstances = result.DBInstances;

    while (result.NextToken) {
        result = await rds.describeDBInstances({NextToken: result.NextToken}).promise();
        DBInstances = [...DBInstances, ...result.DBInstances];
    }

    let Instances = _.flatMap(DBInstances).filter(x => exclude.includes(x.DBInstanceIdentifier) === false);


    // Find unencrypted instances
    let UnencryptedInstances = Instances.filter(instance => instance.kms_key_id === undefined);

    return new RuleResult({
        valid: (UnencryptedInstances.length > 0) ? "fail" : "success",
        message: "RDS instances must be encrypted",
        resources: Instances.map(instance => {
            let unencrypted = instance.kms_key_id === undefined;

            return new Resource({
                is_compliant: unencrypted ? false : true,
                resource_id: instance.DBInstanceIdentifier,
                resource_type: "AWS::RDS::DBInstance",
                message: unencrypted ? `is unencrypted.` : "is encrypted."
            })
        })
    });
};

RDSEncryptionKeyExists.validate = async function(context /*: Context */) {
    const kms = new context.provider.KMS();
    let result = null;
    if (context.config.enabled == true) {
        if (context.instance.kms_key_id) {
            const queryResult = await kms.listKeys({}).promise();
            debug('%O', queryResult);
            debug('%O', context.instance.kms_key_id);
            if (_.find(queryResult.Keys, {KeyArn: context.instance.kms_key_id})) {
                result = {
                    valid: 'success'
                };
            } else {
                result = {
                    valid: 'fail',
                    resource_type: "AWS::RDS::DBInstance",
                    message: `Key [${context.instance.kms_key_id}] not found`
                };
            }
        }
    }
    return result;
};

module.exports = RDSEncryptionKeyExists;

