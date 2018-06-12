
const debug = require('debug')('snitch/dynamodb-point-in-time-recovery');
const get=require('lodash/get');
const filter=require('lodash/filter');
const {RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DynamoDBPontInTimeRecoveryStatus = {};

DynamoDBPontInTimeRecoveryStatus.uuid = "b5ed58c5-2989-4bd3-f2bb-1f245405cb74";
DynamoDBPontInTimeRecoveryStatus.groupName = "DynamoDB";
DynamoDBPontInTimeRecoveryStatus.tags = [["Candid", "1.0", "2"]];
DynamoDBPontInTimeRecoveryStatus.config_triggers = ["AWS::DynamoDB::Table"];
DynamoDBPontInTimeRecoveryStatus.paths = {ContinuousBackupsDescription: "aws_dynamodb_table"};
DynamoDBPontInTimeRecoveryStatus.docs = {
    description: 'Point in time recovery is enabled',
    recommended: true
};
DynamoDBPontInTimeRecoveryStatus.schema = {
    type: 'object',
    properties: {}
};
//------------------------------------------------------------------------------
// livecheck
//------------------------------------------------------------------------------


DynamoDBPontInTimeRecoveryStatus.livecheck = async function(context) {
    const {provider} = context;
    const dynamo = new provider.DynamoDB();
    const tables = await dynamo.listTables().promise();
    const promises = tables.TableNames.map(async (tableName) => {
        let params = {TableName: tableName};
        let result= await dynamo.describeContinuousBackups(params).promise();
        const isEnabled=get(result, 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus', '');

        return {
            is_compliant: isEnabled==='ENABLED' ? true : false,
            resource_id: tableName,
            resource_type: "AWS::DynamoDB::Table",
            message: (isEnabled === 'ENABLED') ? "has point-in-time recovery enabled." : "does not have point-in-time recovery enabled."
        }
    });
    const resources = await Promise.all(promises);
    const isValid=filter(resources,(r)=>!r.is_compliant);

    return new RuleResult({
        valid: (isValid.length > 0) ? "fail" : "success",
        message: "DynamoDB tables should have PointInTimeRecoveryStatus enabled",
        resources
    })
};

DynamoDBPontInTimeRecoveryStatus.validate = function (context /*: Context */) {
    // debug( '%O', context );
    let {config,provider,instance} = context;

    if(instance.PointintimeRecovery){
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
module.exports = DynamoDBPontInTimeRecoveryStatus;

