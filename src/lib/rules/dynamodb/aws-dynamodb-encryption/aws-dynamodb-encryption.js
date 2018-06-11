// @flow
const debug = require('debug')('snitch/dynamodb-encryption');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DynamoDBEncryption = {};

DynamoDBEncryption.uuid = "e391e00a-ddce-4064-80ad-6b0ef351ccc6";
DynamoDBEncryption.groupName = "DynamoDB";
DynamoDBEncryption.tags = [["Candid", "1.0", "1"]];
DynamoDBEncryption.config_triggers = ["AWS::DynamoDB::Table"];
DynamoDBEncryption.paths = {DynamoDBEncryption: "aws_dynamodb_table"};
DynamoDBEncryption.docs = {
    description: 'All DynamoDB tables are encrypted.',
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

DynamoDBEncryption.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */{
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let dynamo = new provider.DynamoDB();

    let tables = await dynamo.listTables().promise();
    let promises = [];
    tables.TableNames.map(x => {
        let params = {TableName: x};
        promises.push(dynamo.describeTable(params).promise())
    });
    let results = await Promise.all(promises);

    // while (results.NextToken) {
    //     let result = await dynamo.describeTable({NextToken: result.NextToken}).promise();
    //     dynamo = [...dynamo, ...result];
    // }

    let Instances = _.flatMap(results, "Table");

    // Find unencrypted instances
    let InstanceIsUnencrypted = instance => !exclude.includes(instance.TableName) && !instance.hasOwnProperty("SSEDescription");
    let UnencryptedInstances = Instances.filter(InstanceIsUnencrypted);

    let resources = Instances.map(x => {
        let isUnencrypted = InstanceIsUnencrypted(x);
        return new Resource({
            is_compliant: isUnencrypted ? false : true,
            resource_id: x.TableName,
            resource_type: "AWS::DynamoDB::Table",
            message: isUnencrypted ? `is unencrypted.` : "is encrypted."
        })
    });

    return new RuleResult({
        valid: (UnencryptedInstances.length > 0) ? "fail" : "success",
        message: "DynamoDB tables should be encrypted",
        resources
    })
};

DynamoDBEncryption.validate = function (context /*: Context */) {
    // debug( '%O', context );
    let {config,provider,instance} = context;

    if(instance.SSEDescription){
        return {valid: 'success'}
    }
    else {
        return {
            valid: 'fail',
            resource_type: "AWS::DynamoDB::Table",
            message: "A dynamodb instance is not encrypted."
        }
    }
};

module.exports = DynamoDBEncryption;

