'use strict';
const debug = require('debug')('snitch/vpc');
const co = require('co');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DefaultVPC = {};

DefaultVPC.uuid = "58c480c4-3f22-4560-983c-ae45ca1d5383";
DefaultVPC.groupName = "VPC";

DefaultVPC.docs = {
    description: 'Default VPC must not exist in the region.',
    recommended: true
};

DefaultVPC.schema = {type: 'boolean'};

DefaultVPC.config_triggers = ["AWS::EC2::VPC"];

DefaultVPC.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let reqTags = config;

    let attributes = yield ec2.describeAccountAttributes().promise();

    let defaultVPC = attributes.AccountAttributes.find(x => x.AttributeName == 'default-vpc');
    if (defaultVPC) {
        let noncompliant_resources = [
            new NonCompliantResource({
                resource_id: JSON.stringify(defaultVPC.AttributeValues[0].AttributeValue),
                resource_type: "AWS::EC2::VPC",
                message: `exists`
            })
        ];
        return new RuleResult({
            valid: "fail",
            message: `Default VPC exists.`,
            noncompliant_resources
        })
    }
    else {
        return {valid: "success"}
    }
});

DefaultVPC.paths = {
    EC2: 'aws_default_vpc'
};

DefaultVPC.validate = co.wrap(function* (context) {
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
});

module.exports = DefaultVPC;

