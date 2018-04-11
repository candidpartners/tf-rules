'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMDoesNotAllowFullAccessPolicies = {};

IAMDoesNotAllowFullAccessPolicies.uuid = "345b6958-9966-4cb7-814b-4daea7857c79";
IAMDoesNotAllowFullAccessPolicies.groupName = "IAM";
IAMDoesNotAllowFullAccessPolicies.tags = [["CIS", "1.1.0", "1.24"]];
IAMDoesNotAllowFullAccessPolicies.config_triggers = ["AWS::IAM::Policy"];
IAMDoesNotAllowFullAccessPolicies.paths = {IAMDoesNotAllowFullAccessPolicies: 'aws_iam_policy'};
IAMDoesNotAllowFullAccessPolicies.docs = {
    description: "No IAM policies allow full administrative privileges.",
    recommended: false
};
IAMDoesNotAllowFullAccessPolicies.schema = {type: 'boolean', default: true};


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

