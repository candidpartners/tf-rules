const {memoize} = require('lodash');
const GetIAMPolicies = require('./iam/get-iam-policies');

function MemomizeOnArgs(func){
    return memoize(GetIAMPolicies, (args) => {
        const newArgs = Object.assign({},args,{provider: undefined});
        return JSON.stringify(newArgs)
    })
}

module.exports = {
    IAM: {
        GetIAMPolicies: MemomizeOnArgs(GetIAMPolicies),
    }
};