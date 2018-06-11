// @flow
const _ = require('lodash');
const {RuleResult, Resource, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2EnsureInstanceRole = {};

EC2EnsureInstanceRole.uuid = "34d1f411-895f-435c-a87c-c40e2b51272f";
EC2EnsureInstanceRole.groupName = "EC2";
EC2EnsureInstanceRole.tags = [["CIS", "1.1.0", "1.21"]];
EC2EnsureInstanceRole.config_triggers = ["AWS::EC2::Instance"];
EC2EnsureInstanceRole.paths = {EC2KeyPairExists: 'aws_instance'};
EC2EnsureInstanceRole.docs = {
    description: 'EC2 Instances must have an instance role.',
    recommended: true,
    tags: ["Live Check"]
};

EC2EnsureInstanceRole.schema = {
    type: 'object',
    properties: {}
};


EC2EnsureInstanceRole.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let ec2 = new context.provider.EC2();

    function getEC2s(params) {
        return ec2.describeInstances(params).promise();
    }

    let result = await getEC2s({});
    let Reservations = result.Reservations;

    while (result.NextToken) {
        result = await getEC2s({NextToken: result.NextToken});
        Reservations.push(result.Reservations);
    }

    let Instances = _.flatMap(Reservations, res => res.Instances);

    function getInstanceRoleARN(Instance) {
        return _.get(Instance, 'IamInstanceProfile.Arn');
    }

    let resources = Instances.map(x => new Resource({
        is_compliant: getInstanceRoleARN(x) ? true : false,
        resource_id: x.InstanceId,
        resource_type: "AWS::EC2::Instance",
        message: getInstanceRoleARN(x) ? `has instance profile ${getInstanceRoleARN(x)}.` : `does not have an instance profile.`
    }));

    return new RuleResult({
        valid: resources.every(x => x.is_compliant) ? "success" : "fail",
        message: "Every EC2 needs an instance profile",
        resources,
    });
};

EC2EnsureInstanceRole.validate = function (context /*: Context */) {
    let isValid = context.instance.iam_instance_profile;

    return new RuleResult({
        valid: isValid ? "success" : "fail",
        message: "EC2 Instance must have instance profile.",
        resources: []
    })
};

module.exports = EC2EnsureInstanceRole;

