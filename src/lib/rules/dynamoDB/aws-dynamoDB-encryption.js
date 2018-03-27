'use strict';
const debug = require('debug')('snitch/dynamoDB-encryption');
const co = require('co');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DynamoDBEncryption = {};

DynamoDBEncryption.uuid = "e391e00a-ddce-4064-80ad-6b0ef351ccc6";
DynamoDBEncryption.groupName = "DynamoDB";

DynamoDBEncryption.docs = {
    description: 'Encrypted DynamoDB table must exist in the region.',
    recommended: true
};

DynamoDBEncryption.schema = {
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

DynamoDBEncryption.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let dynamo = new provider.DynamoDB();
    let reqTags = config;

    let tables = yield dynamo.listTables().promise();
    let promises = [];
    tables.TableNames.map(x => {
        let params = {TableName: x};
        promises.push(dynamo.describeTable(params).promise())
    });
    let results = yield Promise.all(promises);

    while (results.NextToken) {
        let result = yield dynamo.describeTable({NextToken: result.NextToken}).promise();
        dynamo = [...dynamo, ...result];
    }

    let Instances = _.flatMap(results, "Table");

    // Find unencrypted instances
    let UnencryptedInstances = Instances.filter(instance => !exclude.includes(instance.TableName) && !instance.hasOwnProperty("SSEDescription"));

    if (UnencryptedInstances.length > 0) {
        let noncompliant_resources = UnencryptedInstances.map(inst => {
            return {
                id: inst.TableName,
                message: `${inst.TableName} is unencrypted`
            }
        });
        return {
            valid: "fail",
            message: "One or more DynamoDB tables are not encrypted.",
            noncompliant_resources
        }
    }
    else {
        return {valid: "success"}
    }
});

DynamoDBEncryption.paths = {
    DynamoDB: 'aws_dynamodb_instance'
};

DynamoDBEncryption.validate = function* (context) {
    // debug( '%O', context );
    const dynamo = new context.provider.DynamoDB();
    let result = null;
    if (context.config === true) {
        if (context.instance.SSEDescription) {
            result = {
                valid: 'success'
            }
        }
        else {
            result = {
                valid: 'fail',
                message: `${dynamo.tableName} not encrypted`
            }
        }
    }
    return result;
};

module.exports = DynamoDBEncryption;

