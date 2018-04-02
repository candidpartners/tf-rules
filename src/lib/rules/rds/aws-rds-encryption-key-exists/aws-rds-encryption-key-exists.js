'use strict';
const debug = require('debug')('snitch/rds-encryption-exists');
const co = require('co');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RDSEncryptionKeyExists = {};

RDSEncryptionKeyExists.uuid = "196beb21-bb42-4a58-9ea0-0478c5f1042a";
RDSEncryptionKeyExists.groupName = "RDS";
RDSEncryptionKeyExists.tags = [];
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

RDSEncryptionKeyExists.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let rds = new provider.RDS();
    let reqTags = config;

    // Get all RDS instances
    let result = yield rds.describeDBInstances().promise();
    let DBInstances = result.DBInstances;

    while (result.NextToken) {
        let result = yield rds.describeDBInstances({NextToken: result.NextToken}).promise();
        DBInstances = [...DBInstances, ...result.DBInstances];
    }

    let Instances = _.flatMap(DBInstances).filter(x => exclude.includes(x.DBInstanceIdentifier) === false);


    // Find unencrypted instances
    let UnencryptedInstances = Instances.filter(instance => instance.kms_key_id === undefined);

    if (UnencryptedInstances.length > 0) {
        let noncompliant_resources = UnencryptedInstances.map(inst => {
            return new NonCompliantResource({
                resource_id: inst.DBInstanceIdentifier,
                resource_type: "AWS::RDS::DBInstance",
                message: `is unencrypted.`
            })
        });
        return new RuleResult({
            valid: "fail",
            message: "One or more RDS instances are not encrypted.",
            noncompliant_resources
        })
    }
    else {
        return {valid: "success"}
    }
});

RDSEncryptionKeyExists.validate = function* (context) {
    // debug( '%O', context );
    const kms = new context.provider.KMS();
    let result = null;
    if (context.config == true) {
        if (context.instance.kms_key_id) {
            const queryResult = yield kms.listKeys({}).promise();
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

