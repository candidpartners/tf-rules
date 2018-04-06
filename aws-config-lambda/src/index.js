require('dotenv').config();
const AWS = require('aws-sdk');
const _ = require('lodash');
const AWSConfig = new AWS.ConfigService();
const Snitch = require('@candidpartners/snitch');

// Receives the event and context from AWS Lambda.
exports.handler = async function (event, context, callback){
    console.log(event);
    let {resultToken,accountId,invokingEvent, configRuleName} = event;

    // Check if it is a triggered event
    let config_trigger =_.get(invokingEvent,'configurationItem.resourceType',undefined);

    try{
        let config = Snitch.LoadConfigFromFile(__dirname + "/snitch.config.yml");
        let result = await Snitch.Livecheck({
            provider: AWS,
            config,
            config_triggers: config_trigger ? [config_trigger] : []
        });
        console.log({result});
        let failedResults = result
            .filter(x => x)
            .filter(x => x.valid == 'fail');

        console.log(JSON.stringify(failedResults,null,2));
        let nonCompliantResources = _.flatMap(failedResults, x => x.noncompliant_resources || []);
        let resourceEvaluations = nonCompliantResources.map(x => ({
            ComplianceResourceId: x.resource_id,
            ComplianceResourceType: x.resource_type,
            ComplianceType: "NON_COMPLIANT",
            OrderingTimestamp: new Date(),
            Annotation: x.message
        }));

        let params = {
            ResultToken: resultToken,
            Evaluations: resourceEvaluations
        };

        let putEvaluationsResult = await AWSConfig.putEvaluations(params).promise();
        callback(null,{params,putEvaluationsResult});
    } catch (err) {
        console.error(err);
        callback(err,null)

    }
};