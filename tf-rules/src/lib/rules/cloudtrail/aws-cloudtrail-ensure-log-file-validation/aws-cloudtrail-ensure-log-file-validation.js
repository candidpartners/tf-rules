'use strict';
const _ = require('lodash');
const debug = require('debug')('tfrules/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogFileValidation = {};

CloudtrailLogFileValidation.uuid = "87dfba99-8a5e-4a7b-b408-1b41d8088a8a";
CloudtrailLogFileValidation.groupName = "Cloudtrail";

CloudtrailLogFileValidation.docs = {
    description: "Ensures LogFileValidationEnabled is enabled on each Cloudtrail",
    recommended: false
};

CloudtrailLogFileValidation.schema = {type: 'boolean'};

CloudtrailLogFileValidation.paths = {
    CloudtrailLogFileValidation: 'aws_cloudtrail'
};

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

