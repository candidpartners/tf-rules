'use strict';
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMUserPolicyDoesNotExist = {};

IAMUserPolicyDoesNotExist.docs = {
    description: "No IAM policies can be attached directly to a user.",
    recommended: false
};

IAMUserPolicyDoesNotExist.schema = {type: 'boolean'}

IAMUserPolicyDoesNotExist.paths = {
    awsIAMUserPolicyDoesNotExist: 'aws_iam_user_policy_attachment'
};

IAMUserPolicyDoesNotExist.validate = function (context) {
    let instance = context.instance;

    return {
        valid: 'fail',
        message: "CIS 1.16 - IAM Policies must only be attached to groups or roles, not users."
    }
};

module.exports = IAMUserPolicyDoesNotExist;

