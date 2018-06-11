'use strict';
const _ = require('lodash');
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const VpcFlowLogsAreEnabled = {};

VpcFlowLogsAreEnabled.uuid = "7fbba5df-8c3b-4150-b2e0-2bfa221e3c89";
VpcFlowLogsAreEnabled.groupName = "VPC";
VpcFlowLogsAreEnabled.tags = [["CID", "1.1.0", "4.3"]];
VpcFlowLogsAreEnabled.config_triggers = ["AWS::EC2::VPC"];
VpcFlowLogsAreEnabled.paths = {VpcFlowLogsAreEnabled: "aws_flow_log"};
VpcFlowLogsAreEnabled.docs = {description: 'Flow logging should be enabled in all VPCs', recommended: true};
VpcFlowLogsAreEnabled.schema = {
    type: 'object',
    properties: {}
};


VpcFlowLogsAreEnabled.livecheck = async function (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let vpcs = await ec2.describeVpcs().promise();
    let flowLogs = await ec2.describeFlowLogs().promise();

    let vpcIds = vpcs.Vpcs.map(x => x.VpcId);
    let flowLogsVpcs = flowLogs.FlowLogs.map(x => x.ResourceId);
    let vpcsWithFlowLogs = _.intersection(vpcIds, flowLogsVpcs);

    let disabled = vpcIds.filter(x => !vpcsWithFlowLogs.includes(x));

    return new RuleResult({
        valid: (vpcsWithFlowLogs.length !== vpcIds.length) ? "fail" : "success",
        message: "Flow logging should be enabled for all VPCs",
        resources: vpcIds.map(vpc => {
            return new Resource({
                is_compliant: disabled.includes(vpc) ? false : true,
                resource_id: vpc,
                resource_type: "AWS::EC2::VPC",
                message: disabled.includes(vpc) ? "does not have flow logging enabled." : "has flow logging enabled."
            })
        })
    });
};

module.exports = VpcFlowLogsAreEnabled;