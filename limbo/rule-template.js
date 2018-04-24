'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const RuleName = {};

RuleName.uuid = "";
RuleName.groupName = "";
RuleName.tags = [];
RuleName.config_triggers = [];
RuleName.paths = {};
RuleName.docs = {description: '', recommended: true};
RuleName.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        }
    }
};


RuleName.livecheck = async function (context) {
    let {config, provider} = context;

    return new RuleResult({
        valid: () ? "fail" : "success",
        message: "",
        resources: ().map(vpc => {
            return new Resource({
                is_compliant: () ? false : true,
                resource_id: "",
                resource_type: "",
                message: () ? "does not have flow logging enabled" : "has flow logging enabled"
            })
        })
    });
};

module.exports = RuleName;