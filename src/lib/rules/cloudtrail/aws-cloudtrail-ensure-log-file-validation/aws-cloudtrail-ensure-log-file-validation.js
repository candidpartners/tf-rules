// @flow
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogFileValidation = {};

CloudtrailLogFileValidation.uuid = "87dfba99-8a5e-4a7b-b408-1b41d8088a8a";
CloudtrailLogFileValidation.groupName = "CloudTrail";
CloudtrailLogFileValidation.tags= [["CIS","1.1.0","2.2"], ["PCI", "3.2", "10.5.5"]];
CloudtrailLogFileValidation.config_triggers = ["AWS::CloudTrail::Trail"];
CloudtrailLogFileValidation.paths = {CloudtrailLogFileValidation: 'aws_cloudtrail'};
CloudtrailLogFileValidation.docs = {
    description: "Log file validation is enabled on every CloudTrail resource.",
    recommended: false
};
CloudtrailLogFileValidation.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};

CloudtrailLogFileValidation.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();

    let trails = await cloud.describeTrails().promise();
    let disabledTrails = trails.trailList.filter(x => x.LogFileValidationEnabled === false);

    return new RuleResult({
        valid: (disabledTrails.length > 0) ? "fail" : "success",
        message: CloudtrailLogFileValidation.docs.description,
        resources: trails.trailList.map(t => {
            let isDisabled = (t.LogFileValidationEnabled === false);
            return new Resource({
                is_compliant: isDisabled ? false : true,
                resource_id: t.Name,
                resource_type: "AWS::CloudTrail::Trail",
                message: isDisabled ? "does not have log file validation enabled." : "has log file validation enabled."
            })
        })
    });
};

CloudtrailLogFileValidation.validate = function (context /*: Context */) {
    let instance = context.instance;

    if(!instance.enable_log_file_validation)
        return {
            valid: 'fail',
            message: `Cloudtrail ${instance.name} has enable_log_file_validation set to false.`
        };
    else{
        return {
            valid: 'success'
        }
    }
};

module.exports = CloudtrailLogFileValidation;

