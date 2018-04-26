// @flow
'use strict';
const debug = require('debug')('snitch/vpc');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DefaultVPC = {};

DefaultVPC.uuid = "58c480c4-3f22-4560-983c-ae45ca1d5383";
DefaultVPC.groupName = "VPC";
DefaultVPC.tags = [["Candid", "1.0", "15"]];
DefaultVPC.config_triggers = ["AWS::EC2::VPC"];
DefaultVPC.paths = {DefaultVPC: "aws_default_vpc"};
DefaultVPC.docs = {
    description: 'A default VPC does not exist in the region.',
    recommended: true
};
DefaultVPC.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


DefaultVPC.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let reqTags = config;

    let attributes = await ec2.describeAccountAttributes().promise();

    let defaultVPC = attributes.AccountAttributes.find(x => x.AttributeName === 'default-vpc');

    let defaultVPCID = "Default VPC";
    if(defaultVPC)
        defaultVPCID = JSON.stringify(defaultVPC.AttributeValues[0].AttributeValue);

    return new RuleResult({
        valid: defaultVPC ? "fail" : "success",
        message: "There should be no default VPC",
        resources: [
            new Resource({
                is_compliant: defaultVPC ? false : true,
                resource_id: "Default_VPC",
                resource_type: "AWS::EC2::VPC",
                message: defaultVPC ? `${defaultVPCID} exists.` : "No Default VPC Exists."
            })
        ]
    });
};

DefaultVPC.paths = {
    EC2: 'aws_default_vpc'
};

DefaultVPC.validate = async function(context /*: Context */) {
    let {config,instance,provider} = context;

    if(instance.AccountAttributes.length === 0){
        return {valid: 'success'}
    }
    else {
        return {
            valid: 'fail',
            resource_type: "AWS::EC2::Instance",
            message: "A default VPC exists"
        }
    }
};

module.exports = DefaultVPC;

