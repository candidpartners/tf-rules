require('dotenv').config();
const aws = require('aws-sdk');
const config = new aws.ConfigService();

// Helper function used to validate input
function checkDefined(reference, referenceName) {
    if (!reference) {
        throw new Error(`Error: ${referenceName} is not defined`);
    }
    return reference;
}

// Check whether the message type is OversizedConfigurationItemChangeNotification,
function isOverSizedChangeNotification(messageType) {
    checkDefined(messageType, 'messageType');
    return messageType === 'OversizedConfigurationItemChangeNotification';
}

// Get the configurationItem for the resource using the getResourceConfigHistory API.
function getConfiguration(resourceType, resourceId, configurationCaptureTime, callback) {
    config.getResourceConfigHistory({ resourceType, resourceId, laterTime: new Date(configurationCaptureTime), limit: 1 }, (err, data) => {
        if (err) {
            callback(err, null);
        }
        const configurationItem = data.configurationItems[0];
        callback(null, configurationItem);
    });
}

// Convert the oversized configuration item from the API model to the original invocation model.
function convertApiConfiguration(apiConfiguration) {
    apiConfiguration.awsAccountId = apiConfiguration.accountId;
    apiConfiguration.ARN = apiConfiguration.arn;
    apiConfiguration.configurationStateMd5Hash = apiConfiguration.configurationItemMD5Hash;
    apiConfiguration.configurationItemVersion = apiConfiguration.version;
    apiConfiguration.configuration = JSON.parse(apiConfiguration.configuration);
    if ({}.hasOwnProperty.call(apiConfiguration, 'relationships')) {
        for (let i = 0; i < apiConfiguration.relationships.length; i++) {
            apiConfiguration.relationships[i].name = apiConfiguration.relationships[i].relationshipName;
        }
    }
    return apiConfiguration;
}

// Based on the message type, get the configuration item either from the configurationItem object in the invoking event or with the getResourceConfigHistory API in the getConfiguration function.
function getConfigurationItem(invokingEvent) {

    return new Promise((resolve,reject) => {
        checkDefined(invokingEvent, 'invokingEvent');
        if (isOverSizedChangeNotification(invokingEvent.messageType)) {
            const configurationItemSummary = checkDefined(invokingEvent.configurationItemSummary, 'configurationItemSummary');
            getConfiguration(configurationItemSummary.resourceType, configurationItemSummary.resourceId, configurationItemSummary.configurationItemCaptureTime, (err, apiConfigurationItem) => {
                if (err) {
                    reject(err);
                }
                const configurationItem = convertApiConfiguration(apiConfigurationItem);
                resolve(configurationItem);
            });
        } else {
            checkDefined(invokingEvent.configurationItem, 'configurationItem');
            resolve(invokingEvent.configurationItem);
        }
    });
}

// Check whether the resource has been deleted. If the resource was deleted, then the evaluation returns not applicable.
function isApplicable(configurationItem, event) {
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(event, 'event');
    const status = configurationItem.configurationItemStatus;
    const eventLeftScope = event.eventLeftScope;
    return (status === 'OK' || status === 'ResourceDiscovered') && eventLeftScope === false;
}

// In this example, the resource is compliant if it is an instance and its type matches the type specified as the desired type.
// If the resource is not an instance, then this resource is not applicable.
function evaluateChangeNotificationCompliance(configurationItem, ruleParameters) {
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(configurationItem.configuration, 'configurationItem.configuration');
    checkDefined(ruleParameters, 'ruleParameters');

    if (configurationItem.resourceType !== 'AWS::EC2::Instance') {
        return 'NOT_APPLICABLE';
    } else if (ruleParameters.desiredInstanceType === configurationItem.configuration.instanceType) {
        return 'COMPLIANT';
    }
    return 'NON_COMPLIANT';
}

// Receives the event and context from AWS Lambda.
exports.handler = (event, context, callback) => {
    checkDefined(event, 'event');
    const invokingEvent = JSON.parse(event.invokingEvent);
    const ruleParameters = JSON.parse(event.ruleParameters);

    console.log(JSON.stringify({invokingEvent,ruleParameters},null,2));

    getConfigurationItem(invokingEvent)
        .then(configurationItem => {
            let compliance = 'NOT_APPLICABLE';
            const putEvaluationsRequest = {};
            // if (isApplicable(configurationItem, event)) {
            //     // Invoke the compliance checking function.
            //     compliance = evaluateChangeNotificationCompliance(configurationItem, ruleParameters);
            // }

            // Initializes the request that contains the evaluation results.
            // putEvaluationsRequest.Evaluations = [
            //     {
            //         ComplianceResourceType: configurationItem.resourceType,
            //         ComplianceResourceId: configurationItem.resourceId,
            //         ComplianceType: compliance,
            //         OrderingTimestamp: configurationItem.configurationItemCaptureTime,
            //     },
            // ];
            // putEvaluationsRequest.ResultToken = event.resultToken;
            //
            // // Sends the evaluation results to AWS Config.
            // config.putEvaluations(putEvaluationsRequest, (error, data) => {
            //     if (error) {
            //         callback(error, null);
            //     } else if (data.FailedEvaluations.length > 0) {
            //         // Ends the function if evaluation results are not successfully reported to AWS Config.
            //         callback(JSON.stringify(data), null);
            //     } else {
            //         callback(null, data);
            //     }
            // });
        })
        .catch(error => {
            callback(error);
        });
};