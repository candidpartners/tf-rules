'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const KMSKeyRotation = {};

KMSKeyRotation.uuid = "07d3c190-37f7-4699-8498-ef1175033516";
KMSKeyRotation.groupName = "KMS";
KMSKeyRotation.tags = [];
KMSKeyRotation.config_triggers = ["AWS::::Account"];
KMSKeyRotation.paths = {awsIAMUserPolicyDoesNotExist: 'aws_kms_key'};
KMSKeyRotation.docs = {
    description: "All KMS keys are rotated.",
    recommended: false
};
KMSKeyRotation.schema = {type: 'boolean'};


KMSKeyRotation.validate = function (context) {
    let {config, instance} = context;

    let enabled = config;

    if (!enabled)
        return {valid: 'success'};

    if (instance.enable_key_rotation) {
        return {valid: 'success'};
    }
    else{
        return {
            valid: 'fail',
            message: "KMS key rotation needs to be enabled."
        }
    }
};

module.exports = KMSKeyRotation;
