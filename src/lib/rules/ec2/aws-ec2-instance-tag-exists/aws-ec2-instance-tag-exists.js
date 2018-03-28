const _ = require('lodash');

const co = require('co');
const debug = require('debug')('snitch/tag-exists');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagExists = {};

EC2TagExists.uuid = "cb6da3e8-cff5-490c-b200-4d43f8cc0632";
EC2TagExists.groupName = "EC2";

EC2TagExists.docs = {
    description: "Required tagging must exist",
    recommended: false
};

EC2TagExists.schema = {
    type: 'array',
    items: {
        type: 'string'
    }
};



EC2TagExists.config_triggers = ["AWS::EC2::Instance"];

EC2TagExists.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let ec2 = new provider.EC2();
    let reqTags = config;

    // Get all EC2 Instances
    let result = yield ec2.describeInstances().promise();
    let Reservations = result.Reservations;

    while (result.NextToken) {
        let result = yield ec2.describeInstances({NextToken: result.NextToken}).promise();
        Reservations = [...Reservations, ...result.Reservations];
    }

    let Instances = _.flatMap(Reservations, 'Instances');


    // Find instances without tags
    let InstancesWithoutTags = Instances.filter(instance => {
        let Tags = instance.Tags.map(x => x.Key);
        let MissingRequiredTags = _.difference(reqTags, Tags);
        return MissingRequiredTags.length > 0
    });

    if (InstancesWithoutTags.length > 0) {
        let noncompliant_resources = InstancesWithoutTags.map(inst => {
            let {Tags, InstanceId} = inst;
            let missingTags = _.difference(reqTags, Tags.map(x => x.Key));
            return {
                resource_id: InstanceId,
                resource_type: "AWS::EC2::Instance",
                message: `Missing tags ${missingTags}`
            }
        });
        return {
            valid: "fail",
            message: "One or more EC2 instances are missing required tags.",
            noncompliant_resources
        }
    }
    else {
        return {valid: "success"}
    }
});


EC2TagExists.paths = {
    awsInstance: 'aws_instance'
};

EC2TagExists.validate = function (context) {
    let reqTags = context.config;

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

