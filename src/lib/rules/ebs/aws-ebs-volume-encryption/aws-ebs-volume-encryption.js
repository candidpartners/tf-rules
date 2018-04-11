// @flow
const debug = require('debug')('snitch/ebs-encryption');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EBSVolumeEncryption = {};

EBSVolumeEncryption.uuid = "d8a29e45-d30a-4492-8380-fe1da3ed0cba";
EBSVolumeEncryption.groupName = "EBS";
EBSVolumeEncryption.tags = [["Snitch", "1.0", "2"]];
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


EBSVolumeEncryption.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let ec2 = new provider.EC2();

    let volumes = await ec2.describeVolumes().promise();

    let isVolumeUnencrypted = x => !exclude.includes(x.VolumeId) && x.Encrypted === false
    let UnencryptedVolumes = volumes.Volumes.filter(isVolumeUnencrypted);

    return new RuleResult({
        valid: (UnencryptedVolumes.length > 0) ? "fail" : "success",
        message: "EBS Volumes must be encrypted",
        resources: volumes.Volumes.map(x => {
            let isUnencrypted = isVolumeUnencrypted(x);
            return new Resource({
                is_compliant: isUnencrypted ? false : true,
                resource_id: x.VolumeId,
                resource_type: "AWS::EC2::Volume",
                message: isUnencrypted ? 'is unencrypted.' : "is encrypted"
            })

        })
    });
};

EBSVolumeEncryption.validate = function (context /*: Context */) {
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
};

module.exports = EBSVolumeEncryption;

