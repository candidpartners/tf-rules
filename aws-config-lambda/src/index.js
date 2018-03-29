require('dotenv').config();
const AWS = require('aws-sdk');
const co = require('co');
const _ = require('lodash');
const AWSConfig = new AWS.ConfigService();
const Snitch = require('@candidpartners/snitch');

// Receives the event and context from AWS Lambda.
exports.handler = co.wrap(function * (event, context, callback){
    console.log(event);
    let {resultToken,accountId,invokingEvent} = event;

    // Check if it is a triggered event
    let config_trigger =_.get(invokingEvent,'configurationItem.resourceType',undefined);

    try{
        let config = Snitch.LoadConfigFromFile(__dirname + "/snitch.config.yml");
        let result = yield Snitch.Livecheck({
            provider: AWS,
            config,
            config_triggers: config_trigger ? [config_trigger] : []
        });
        let failedResults = result.filter(x => x.valid == 'fail');

        // let isAccountCompliant = failedResults.length == 0;
        // let Annotation = JSON.stringify(failedResults.map(x => x.message),null,2);

        console.log(JSON.stringify(failedResults,null,2));
        let nonCompliantResources = _.flatMap(failedResults, x => x.noncompliant_resources);
        let resourceEvaluations = nonCompliantResources.map(x => ({
            ComplianceResourceId: x.resource_id,
            ComplianceResourceType: "x.resource_type",
            ComplianceType: "NON_COMPLIANT",
            OrderingTimestamp: new Date(),
            Annotation: x.message
        }))

        // let resourceEvaluations = failedResults.map(result => {
        //     return {
        //         ComplianceResourceId: result.resource_id,
        //     }
        // });

        let params = {
            ResultToken: resultToken,
            Evaluations: resourceEvaluations
            // Evaluations: [
            //     {
            //         ComplianceResourceId: accountId, //'STRING_VALUE', /* required */
            //         ComplianceResourceType: "AWS::::Account", //'STRING_VALUE', /* required */
            //         ComplianceType: (isAccountCompliant) ? "COMPLIANT" : "NON_COMPLIANT", //"NON_COMPLIANT", //COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE | INSUFFICIENT_DATA, /* required */
            //         OrderingTimestamp: new Date(), //|| 'Wed Dec 31 1969 16:00:00 GMT-0800 (PST)' || 123456789, /* required */
            //         Annotation
            //     },
            // ],
        };
        //
        // console.log(params);
        let putEvaluationsResult = yield AWSConfig.putEvaluations(params).promise();
        callback(null,{params,putEvaluationsResult});
    } catch (err) {
        callback(err)
    }
});