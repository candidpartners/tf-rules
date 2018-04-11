'use strict';
const debug = require('debug')('snitch/ebs-encryption');
const co = require('co');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EBSVolumeEncryption = {};

EBSVolumeEncryption.uuid = "d8a29e45-d30a-4492-8380-fe1da3ed0cba";
EBSVolumeEncryption.groupName = "EBS";
EBSVolumeEncryption.tags = [["Candid", "1.0", "2"]];
EBSVolumeEncryption.config_triggers = ["AWS::EC2::Volume"];
EBSVolumeEncryption.paths = {EBSVolumeEncryption: 'aws_ebs_volume'};
EBSVolumeEncryption.docs = {
    description: "All EBS volumes have encryption enabled.",
    recommended: false
};
EBSVolumeEncryption.schema = {
    type: 'object',
    required: ["enabled"],
    properties: {
        enabled: {type: "boolean", default: true},
        exclude: {
            type: 'array',
            items: {
                type: 'string'
            }
        },
    }
}


EBSVolumeEncryption.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let ec2 = new provider.EC2();
    let reqTags = config;

    let volumes = yield ec2.describeVolumes().promise();

    let UnencryptedVolumes = volumes.Volumes.filter(x => !exclude.includes(x.VolumeId) && x.Encrypted === false);

    if (UnencryptedVolumes.length > 0) {
        let noncompliant_resources = UnencryptedVolumes.map(vol => {
            return new NonCompliantResource({
                resource_id: vol.VolumeId,
                resource_type: "AWS::EC2::Volume",
                message: 'is unencrypted.'
            })
        });
        // console.log(noncompliant_resources);
        return new RuleResult({
            valid: "fail",
            message: "One or more EBS volumes are not encrypted.",
            noncompliant_resources
        })
    }
    else {
        return {valid: "success"}
    }
});

EBSVolumeEncryption.validate = co.wrap(function* (context) {
    let {config, instance, provider} = context;

    if (instance.encrypted === true) {
        return {valid: 'success'}
    }
    else {
        return {
            valid: 'fail',
            resource_type: "AWS::EC2::Volume",
            message: "A dynamodb instance is not encrypted"
        }
    }
});

module.exports = EBSVolumeEncryption;

