const {memoize} = require('lodash');
const GetIAMPolicies = require('./iam/get-iam-policies');

function MemomizeOnArgs(func){
    return memoize(GetIAMPolicies, (args) => JSON.stringify(args))
}

module.exports = {
    IAM: {
        GetIAMPolicies: MemomizeOnArgs(GetIAMPolicies),
    }
};