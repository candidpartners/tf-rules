'use strict';
const _ = require('lodash');
const co = require('co');
const debug = require('debug')('snitch/tag-format');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogFileValidation = {};

CloudtrailLogFileValidation.uuid = "87dfba99-8a5e-4a7b-b408-1b41d8088a8a";
CloudtrailLogFileValidation.groupName = "CloudTrail";
CloudtrailLogFileValidation.tags= ["CIS | 1.1.0 | 2.2"];
CloudtrailLogFileValidation.config_triggers = ["AWS::CloudTrail::Trail"];
CloudtrailLogFileValidation.paths = {CloudtrailLogFileValidation: 'aws_cloudtrail'};
CloudtrailLogFileValidation.docs = {
    description: "Log file validation is enabled on every CloudTrail resource.",
    recommended: false
};
CloudtrailLogFileValidation.schema = {
    type: 'boolean',
    default: true
};

CloudtrailLogFileValidation.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();

    let trails = yield cloud.describeTrails().promise();
    let disabledTrails = trails.trailList.filter(x => x.LogFileValidationEnabled === false);

    if (disabledTrails.length > 0) {
        return new RuleResult({
            valid: "fail",
            message: "One or more CloudTrail resources have log file validation disabled.",
            noncompliant_resources: disabledTrails.map(x => new NonCompliantResource({
                resource_id: x.Name,
                resource_type: "AWS::CloudTrail::Trail",
                message: "has log file validation disabled."
            }))
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

CloudtrailLogFileValidation.validate = function (context) {
    let instance = context.instance;

    if(!instance.enable_log_file_validation)
        return {
            valid: 'fail',
            message: `Cloudtrail ${instance.name} has enable_log_file_validation set to false`
        };
    else{
        return {
            valid: 'success'
        }
    }
};

module.exports = CloudtrailLogFileValidation;

