const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

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
RuleName.schema = {type: 'boolean'};


RuleName.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    if (true) {
        return new RuleResult({
            valid: "fail",
            message: "",
            noncompliant_resources: {
                resource_id: "",
                resource_type: "",
                message: ""
            }
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = RuleName;