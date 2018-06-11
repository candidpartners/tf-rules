// @flow
const debug = require('debug')('snitch/ec2-key-pair-exists');
const _ = require('lodash');
const {RuleResult, Resource, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2KeyPairExists = {};

EC2KeyPairExists.uuid = "25c51c51-c2c5-4f5d-bfe4-bf900dc86f3a";
EC2KeyPairExists.groupName = "EC2";
EC2KeyPairExists.tags = [["Candid", "1.0", "6"]];
EC2KeyPairExists.config_triggers = ["AWS::EC2::Instance"];
EC2KeyPairExists.paths = {EC2KeyPairExists: 'aws_instance'};
EC2KeyPairExists.docs = {
    description: 'An EC2 key pair exists in the account and region.',
    recommended: true,
    tags: ["Live Check"]
};
EC2KeyPairExists.schema = {
    type: 'object',
    properties: {}
};


EC2KeyPairExists.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
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
    let NoKeyInstances = Instances.filter(x => !x.KeyName);

    return new RuleResult({
        valid: (NoKeyInstances.length > 0) ? "fail" : "success",
        message: "EC2 Instances must have a valid keypair",
        resources: Instances.map(inst => {
            let missingKey = !inst.KeyName;
            return new Resource({
                is_compliant: missingKey ? false : true,
                resource_id: inst.InstanceId,
                resource_type: "AWS::EC2::Instance",
                message: missingKey ? "does not have a key pair." : "has a valid key pair."
            })
        })
    })
};

EC2KeyPairExists.validate = async function(context /*: Context */) {
    // debug( '%O', context );

    const ec2 = new context.provider.EC2();
    let result = null;
    if (context.config.enabled === true) {
        // debug('Instance: %j', context.instance)
        if (context.instance.key_name) {
            const queryResult = await ec2.describeKeyPairs({
                Filters: [
                    {
                        'Name': 'key-name',
                        'Values': [context.instance.key_name]
                    }
                ]
            }).promise();
            debug('Query Result: %O', queryResult);
            debug('Instance Key: %O', context.instance.key_name);
            if (queryResult.KeyPairs.length > 0) {
                result = {
                    valid: 'success'
                };
            } else {
                result = {
                    valid: 'fail',
                    resource_type: "AWS::EC2::Instance",
                    message: `Key [${context.instance.key_name}] not found`
                };
            }
        }
        else {
            result = {
                valid: 'fail',
                resource_type: "AWS::EC2::Instance",
                message: `Key [${context.instance.key_name}] not found`
            };
        }
    }
    return result;
};

module.exports = EC2KeyPairExists;

