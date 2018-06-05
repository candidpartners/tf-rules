const {memoize} = require('lodash');
const GetIAMPolicies = require('./iam/get-iam-policies');
const GetIAMCredentialReport=require('./iam/get-iam-credential-report-services');

function MemomizeOnArgs(func){
    return memoize(func, (args) => {
        const newArgs = Object.assign({},args,{provider: undefined});
        return JSON.stringify(newArgs)
    })
}

module.exports = {
    IAM: {
        GetIAMPolicies: MemomizeOnArgs(GetIAMPolicies),
        GetIAMCredentialReport : MemomizeOnArgs(GetIAMCredentialReport)
    }
};