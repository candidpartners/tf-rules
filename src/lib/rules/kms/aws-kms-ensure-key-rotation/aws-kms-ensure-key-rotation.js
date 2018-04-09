'use strict';
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

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
KMSKeyRotation.schema = {type: 'boolean'};

KMSKeyRotation.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let kms = new provider.KMS();
    let filters = [
        "arn:aws:kms:us-west-2:421471939647:key/9890eec1-6d8e-4d1a-a4c9-a11b28fd92c0",
        "arn:aws:kms:us-west-2:421471939647:key/fdbcb545-598c-454e-b26a-1504e4ee1600"];

    let {Keys} = yield kms.listKeys().promise();
    let filteredKeys = Keys.filter(x => !filters.includes(x.KeyArn));
    let promises = filteredKeys.map(key => kms.getKeyRotationStatus({KeyId: key.KeyArn}).promise());
    try {
        let keys = filteredKeys.map(x => x);
        let result = yield Promise.all(promises);
        let combined = _.zip(keys, result);
        let noncompliant_resources = combined.filter(x => x[1].KeyRotationEnabled === false);

        if (noncompliant_resources.length > 0) {
            return new RuleResult({
                valid: "fail",
                message: "One or more of your KMS keys does not have rotation enabled.",
                noncompliant_resources: noncompliant_resources.map(x => new NonCompliantResource({
                    resource_id: x[0].KeyArn,
                    resource_type: "AWS::KMS::Key",
                    message: "does not have rotation enabled."
                }))
            })
        }
        else return new RuleResult({valid: "success"})
    } catch (err) {
        console.error(err.message);
    }
});

KMSKeyRotation.validate = function (context) {
    let {config, instance} = context;

    let enabled = config;

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
