'use strict';
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const VPCEnsureFlowLog = {};

VPCEnsureFlowLog.uuid = "950d9cf9-549b-4e75-93b7-5104323775cb";
VPCEnsureFlowLog.groupName = "VPC";

VPCEnsureFlowLog.docs = {
    description: "All VPCs have a flow_log resource.",
    recommended: false
};

VPCEnsureFlowLog.schema = {type: 'boolean'};

VPCEnsureFlowLog.paths = {
    awsIAMAccountPasswordPolicy: 'aws_vpc'
};

VPCEnsureFlowLog.validate = function (context) {
    let {config,instance,plan} = context;

    console.log(JSON.stringify({config,instance,plan},null,2));

    let enabled = config;
    if(!enabled)
        return { valid: 'success' };

    let flowLogs = _.get(plan,'aws_flow_log',{});
    let associatedFlowLog = _.find(flowLogs, (fl_instance,fl_name) => {
        fl_instance
    })




    return {
        success: 'fail',
        error: 'not implemented'
    };

};

module.exports = VPCEnsureFlowLog;

