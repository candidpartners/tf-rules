const AWS = require('aws-sdk');
const debug = require('debug')('tfrules/ec2-key-pair-exists');
const co = require('co');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2KeyPairExists = {};

EC2KeyPairExists.uuid = "25c51c51-c2c5-4f5d-bfe4-bf900dc86f3a";
EC2KeyPairExists.groupName = "EC2";

EC2KeyPairExists.docs = {
    description: 'EC2 Keypair must exist in the account and region',
    recommended: true,
    tags: [ "Live Check"]
};

EC2KeyPairExists.schema = {type: 'boolean'};

EC2KeyPairExists.paths = {
    rdsInstance: 'aws_instance'
};


EC2KeyPairExists.livecheck = co.wrap(function* (context) {
    let ec2 = new context.provider.EC2();

    function getEC2s(params) {
        return ec2.describeInstances(params).promise();
    }

    let result = yield getEC2s({});
    let Reservations = result.Reservations;

    while(result.NextToken){
        result = yield getEC2s({NextToken: result.NextToken});
        Reservations.push(result.Reservations);
    }

    let Instances = _.flatMap(Reservations,res => res.Instances);
    let NoKeyInstances = Instances.filter(x => !x.KeyName);

    if(NoKeyInstances.length > 0)
        return { valid: 'fail', message: "One or more of your EC2 instances do not have a Key Pair." };
    else
        return {valid: 'success'};
});

EC2KeyPairExists.validate = function* (context) {
    // debug( '%O', context );

    const ec2 = new context.provider.EC2();
    let result = null;
    if (context.config == true) {
        // debug('Instance: %j', context.instance)
        if (context.instance.key_name) {
            const queryResult = yield ec2.describeKeyPairs({
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
                    message: `Key [${context.instance.key_name}] not found`
                };
            }
        }
    }
    return result;
};

module.exports = EC2KeyPairExists;

