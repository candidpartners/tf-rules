'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogsAreEncrypted = {};

CloudtrailLogsAreEncrypted.uuid = "686cbf59-c41a-4b7f-ae4a-7f50bf91d354";
CloudtrailLogsAreEncrypted.groupName = "Cloudtrail";

CloudtrailLogsAreEncrypted.docs = {
    description: "Ensures a KMS key is provided for all cloudtrail resources.",
    recommended: false
};

CloudtrailLogsAreEncrypted.schema = { type: 'boolean' };

CloudtrailLogsAreEncrypted.paths = {
    CloudtrailLogFileValidation: 'aws_cloudtrail'
};

CloudtrailLogsAreEncrypted.validate = function (context) {
    let {config, instance, plan} = context;

    let active = config;
    if(active === false)
        return { valid:"success" }

    if(instance.kms_key_id){
        return { valid:"success" }
    }
    else{
        return {
            valid: "fail",
            message: "Cloudtrail logs must be encrypted. Please set a kms_key_id"
        }
    }
};

module.exports = CloudtrailLogsAreEncrypted;

