'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMUserPolicyDoesNotExist = {};

IAMUserPolicyDoesNotExist.uuid = "1d00c52d-ad5b-40a7-bcaf-3a3ba5f86873";
IAMUserPolicyDoesNotExist.groupName = "IAM";
IAMUserPolicyDoesNotExist.tags = ["CIS | 1.1.0 | 1.16"];
IAMUserPolicyDoesNotExist.config_triggers = ["AWS::IAM:User"];
IAMUserPolicyDoesNotExist.paths = {awsIAMUserPolicyDoesNotExist: 'aws_iam_user_policy_attachment'};
IAMUserPolicyDoesNotExist.docs = {
    description: "IAM policies are attached only to groups or roles.",
    recommended: false
};
IAMUserPolicyDoesNotExist.schema = {type: 'boolean', default: true};


IAMUserPolicyDoesNotExist.validate = function (context) {
    let instance = context.instance;

    return {
        valid: 'fail',
        message: "CIS 1.16 - IAM Policies must only be attached to groups or roles, not users."
    }
};

module.exports = IAMUserPolicyDoesNotExist;

