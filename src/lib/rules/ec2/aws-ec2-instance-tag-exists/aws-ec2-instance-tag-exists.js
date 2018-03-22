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

EC2TagExists.paths = {
    awsInstance: 'aws_instance'
};

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
        let missingTags = _.difference(reqTags, InstancesWithoutTags[0].Tags.map(x => x.Key));
        let {InstanceId} = InstancesWithoutTags[0];
        return {valid: "fail", message: `Not all EC2 instances have required tags. ${InstanceId} is missing tags ${missingTags}`}
    }
    else {
        return {valid: "success"}
    }
});


EC2TagExists.validate = function (context) {
    let reqTags = context.config;

    debug('Tag List: %j', reqTags);

    let missingTags = _.difference(reqTags, _.keys(context.instance.tags));
    debug('Missing Tags: %j', missingTags);

    let message = missingTags.map(tag => `${tag} tag is missing`);

    if (missingTags.length === 0) {
        return { valid: 'success', };
    } else {
        return { valid: 'fail', message };
    }
};

module.exports = EC2TagExists;

