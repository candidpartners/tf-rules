'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogFileValidation = {};

CloudtrailLogFileValidation.uuid = "87dfba99-8a5e-4a7b-b408-1b41d8088a8a";
CloudtrailLogFileValidation.groupName = "CloudTrail";
CloudtrailLogFileValidation.config_triggers = ["AWS::CloudTrail::Trail"];
CloudtrailLogFileValidation.paths = {CloudtrailLogFileValidation: 'aws_cloudtrail'};
CloudtrailLogFileValidation.docs = {
    description: "Log file validation is enabled on each CloudTrail",
    recommended: false
};
CloudtrailLogFileValidation.schema = {type: 'boolean'};


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

