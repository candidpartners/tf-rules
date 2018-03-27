'use strict';
const debug = require('debug')('snitch/default-vpc');
const co = require('co');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const DefaultVPC = {};

DefaultVPC.uuid = "58c480c4-3f22-4560-983c-ae45ca1d5383";
DefaultVPC.groupName = "Default VPC";

DefaultVPC.docs = {
    description: 'Default VPC must not exist in the region.',
    recommended: true
};

DefaultVPC.schema = {type: 'boolean'};

DefaultVPC.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let reqTags = config;

    let attributes = yield ec2.describeAccountAttributes().promise();
    let attributeNames = attributes.AccountAttributes.map(x => x.AttributeName);

    if (attributeNames.includes("default-vpc")) {
        let vpcId = attributes.AccountAttributes.find(x => x.AttributeName === "default-vpc");
        let noncompliant_resource = Object.values(vpcId.AttributeValues[0]);

        return {
            valid: "fail",
            message: `Default VPC ${noncompliant_resource} exists.`,
        }
    }
    else {
        return {valid: "success"}
    }
});

DefaultVPC.paths = {
    EC2: 'aws_ec2_instance'
};

DefaultVPC.validate = function* (context) {
    // debug( '%O', context );
    const ec2 = new context.provider.ec2();
    let result = null;
    if (context.config === true) {
        let attributes = context.instance.AccountAttributes.map(x => x.AttributeName);
        if (!attributes.includes("default-vpc")) {
            result = {
                valid: 'success'
            }
        }
        else if (attributes.includes("default-vpc")) {
            result = {
                valid: 'fail',
                message: `${ec2} contains a default VPC`
            }
        }
    }
    return result;
};

module.exports = DefaultVPC;

