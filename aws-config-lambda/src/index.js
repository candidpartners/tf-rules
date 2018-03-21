require('dotenv').config();
const aws = require('aws-sdk');
const config = new aws.ConfigService();

// Receives the event and context from AWS Lambda.
exports.handler = (event, context, callback) => {
    console.log(event);
    let {resultToken,accountId} = event;

    let params = {
        ResultToken: resultToken,
        Evaluations: [
            {
                ComplianceResourceId: accountId, //'STRING_VALUE', /* required */
                ComplianceResourceType: "AWS::::Account", //'STRING_VALUE', /* required */
                ComplianceType: "NON_COMPLIANT", //COMPLIANT | NON_COMPLIANT | NOT_APPLICABLE | INSUFFICIENT_DATA, /* required */
                OrderingTimestamp: new Date(), //|| 'Wed Dec 31 1969 16:00:00 GMT-0800 (PST)' || 123456789, /* required */
                Annotation: 'This account is broken.'
            },
        ],
    };

    config.putEvaluations(params).promise()
        .then(data => callback(null,data))
        .catch(err => callback(err))
};