// @flow
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const KMSKeyRotation = {};

KMSKeyRotation.uuid = "07d3c190-37f7-4699-8498-ef1175033516";
KMSKeyRotation.groupName = "KMS";
KMSKeyRotation.tags = [["CIS", "1.1.0", "2.8"]];
KMSKeyRotation.config_triggers = ["AWS::::Account"];
KMSKeyRotation.paths = {awsIAMUserPolicyDoesNotExist: 'aws_kms_key'};
KMSKeyRotation.docs = {
    description: "All KMS keys are rotated.",
    recommended: false
};
KMSKeyRotation.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};

KMSKeyRotation.livecheck = async function(context /*: Context*/) /*: Promise<RuleResult>*/ {
    let {config, provider} = context;
    let kms = new provider.KMS();
    let filters = [
        "arn:aws:kms:us-west-2:421471939647:key/9890eec1-6d8e-4d1a-a4c9-a11b28fd92c0",
        "arn:aws:kms:us-west-2:421471939647:key/fdbcb545-598c-454e-b26a-1504e4ee1600"];

    let {Keys} = await kms.listKeys().promise();
    let filteredKeys = Keys.filter(x => !filters.includes(x.KeyArn));
    let promises = filteredKeys.map(key => kms.getKeyRotationStatus({KeyId: key.KeyArn}).promise());
    try {
        let keys = filteredKeys.map(x => x);
        let result = await Promise.all(promises);
        let combined = _.zip(keys, result);
        let noncompliant_resources = combined.filter(x => x[1].KeyRotationEnabled === false);

        return new RuleResult({
            valid: (noncompliant_resources.length > 0) ? "fail" : "success",
            message: KMSKeyRotation.docs.description,
            resources: combined.map(x => {
                let is_compliant = (x[1].KeyRotationEnabled) ? true : false
                return new Resource({
                    is_compliant,
                    resource_id: x[0].KeyArn,
                    resource_type: "AWS::KMS::Key",
                    message: (is_compliant) ? "has key rotation enabled." : "does not have key rotation enabled."
                })
            })
        })

    } catch (err) {
        console.error(err.message);
        return new RuleResult({
            valid: "fail",
            message: err.message,
            resources:[{
                is_compliant: false,
                resource_id: "Snitch_Error",
                resource_type: "AWS::KMS::Key",
                message:err.message,
            }],
        })
    }
};

KMSKeyRotation.validate = function (context /*: Context */) {
    let {config, instance} = context;

    let enabled = config.enabled;

    if (!enabled)
        return {valid: 'success'};

    if (instance.enable_key_rotation) {
        return {valid: 'success'};
    }
    else {
        return {
            valid: 'fail',
            message: "KMS key rotation is not enabled for one or more keys."
        }
    }
};

module.exports = KMSKeyRotation;
