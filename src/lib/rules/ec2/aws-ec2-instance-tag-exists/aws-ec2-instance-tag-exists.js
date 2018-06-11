// @flow
const _ = require('lodash');
const debug = require('debug')('snitch/tag-exists');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagExists = {};

EC2TagExists.uuid = "cb6da3e8-cff5-490c-b200-4d43f8cc0632";
EC2TagExists.groupName = "EC2";
EC2TagExists.tags = [["Candid", "1.0", "4"]];
EC2TagExists.config_triggers = ["AWS::EC2::Instance"];
EC2TagExists.paths = {EC2TagExists: "aws_instance"};
EC2TagExists.docs = {
    description: "Required EC2 instance tags exist.",
    recommended: false
};
EC2TagExists.schema = {
    type: 'object',
    properties: {
        names: {
            title: "Names",
            type: 'array',
            items: {
                type: 'string'
            }
        }
    }
};



EC2TagExists.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let reqTags = config.names;

    // Get all EC2 Instances
    let result = await ec2.describeInstances().promise();
    let Reservations = result.Reservations;

    while (result.NextToken) {
        result = await ec2.describeInstances({NextToken: result.NextToken}).promise();
        Reservations = [...Reservations, ...result.Reservations];
    }

    let Instances = _.flatMap(Reservations, 'Instances');


    // Find instances without tags
    let InstancesWithoutTags = Instances.filter(instance => {
        let Tags = instance.Tags.map(x => x.Key);
        let MissingRequiredTags = _.difference(reqTags, Tags);
        return MissingRequiredTags.length > 0
    });

    let res = new RuleResult({
        valid: (InstancesWithoutTags.length > 0) ? "fail" : "success",
        message: "EC2 Instances must have specified tags",
        resources: Instances.map(instance => {
            let {Tags, InstanceId} = instance;
            let missingTags = _.difference(reqTags, Tags.map(x => x.Key));
            let hasMissingTags = missingTags.length > 0;

            return new Resource({
                is_compliant: hasMissingTags ? false : true,
                resource_id: InstanceId,
                resource_type: "AWS::EC2::Instance",
                message: hasMissingTags ? `is missing tags ${missingTags}.` : "has all required tags."
            })
        })
    });
    return res;
};


EC2TagExists.paths = {
    awsInstance: 'aws_instance'
};

EC2TagExists.validate = function (context /*: Context */) {
    let reqTags = context.config.names;

    debug('Tag List: %j', reqTags);

    let missingTags = _.difference(reqTags, _.keys(context.instance.tags));
    debug('Missing Tags: %j', missingTags);

    let message = missingTags.map(tag => `${tag} tag is missing`);

    if (missingTags.length === 0) {
        return {valid: 'success',};
    } else {
        return {
            valid: 'fail',
            resource_type:"AWS::EC2::Instance",
            message
        };
    }
};

module.exports = EC2TagExists;

