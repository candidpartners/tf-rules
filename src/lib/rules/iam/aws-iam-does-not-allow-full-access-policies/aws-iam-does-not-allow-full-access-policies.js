'use strict';
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMDoesNotAllowFullAccessPolicies = {};

IAMDoesNotAllowFullAccessPolicies.docs = {
    description: "No IAM policies can allow Action:* on Resource: *",
    recommended: false
};

IAMDoesNotAllowFullAccessPolicies.schema = {type: 'boolean'};

IAMDoesNotAllowFullAccessPolicies.paths = {
    IAMDoesNotAllowFullAccessPolicies: 'aws_iam_policy'
};

IAMDoesNotAllowFullAccessPolicies.validate = function (context) {
    let instance = context.instance;

    let policy = instance.policy
        .replace(/\s/g,'') //Remove all whitespace
        .replace(/\\n/g,"") //Remove all newline characters
        .replace(/\\/g ,""); //Remove weird left over //

    let json = JSON.parse(policy);

    // Function to handle Actions and Resources being either single string or array
    function isOrIncludes(objOrArray,match){
        if (_.isArray(objOrArray))
            return objOrArray.includes(match)
        else
            return objOrArray === match
    }

    let StatementsWithAllowAllOnAllResources = _.get(json,"Statement",[])
        .filter(x => {
            return isOrIncludes(x.Action,"*") && isOrIncludes(x.Resource,"*")
        });

    if(StatementsWithAllowAllOnAllResources.length > 0){
        return {
            valid: 'fail',
            message: `CIS 1.24 - IAM Policies must not allow Action: * on Resource: *. Please check policy ${instance.name}`
        }
    }
    else{
        return {
            valid: 'success',
        }
    }

};

module.exports = IAMDoesNotAllowFullAccessPolicies;

