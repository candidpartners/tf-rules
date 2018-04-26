// @flow
const Papa = require('papaparse');
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMNoPoliciesUseDefaultKMSKeys = {};

IAMNoPoliciesUseDefaultKMSKeys.uuid = "aacd1ad6-acf0-49b4-bc00-883599007677";
IAMNoPoliciesUseDefaultKMSKeys.groupName = "IAM";
IAMNoPoliciesUseDefaultKMSKeys.tags = [];
IAMNoPoliciesUseDefaultKMSKeys.config_triggers = ["AWS::IAM::Policy"];
IAMNoPoliciesUseDefaultKMSKeys.paths = {};
IAMNoPoliciesUseDefaultKMSKeys.docs = {
    description: 'No IAM policies use any Default KMS (alias/aws) keys.',
    recommended: false
};
IAMNoPoliciesUseDefaultKMSKeys.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


IAMNoPoliciesUseDefaultKMSKeys.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */{
    const KMS = new context.provider.KMS();

    const Policies = await context.services.IAM.GetIAMPolicies({provider: context.provider, additionalParams: {Scope: "Local"}});
    const Aliases = await KMS.listAliases({}).promise();

    let DefaultAliases = Aliases.Aliases.filter(x => x.AliasName.includes("alias/aws/"));

    let resources = Policies.map(({Policy,PolicyVersion}) => {

        // Function to tell if a policy document uses a default key
        function doesPolicyVersionUseKey(PolicyVersion){
            let DocumentString = JSON.stringify(PolicyVersion.Document);

            for(let i = 0; i < DefaultAliases.length; i++){
                let alias = DefaultAliases[i];
                if(DocumentString.includes(alias.AliasName)) return true;
                if(DocumentString.includes(alias.AliasArn)) return true;
                if(DocumentString.includes(alias.TargetKeyId)) return true;
            }
            return false;
        }

        // See if the Policy is compliant, and report back
        let is_compliant = doesPolicyVersionUseKey(PolicyVersion) ? false : true;
        return new Resource({
            is_compliant,
            resource_id: Policy.PolicyName,
            resource_type: "AWS::IAM::Policy",
            message: is_compliant ? "does not use any default KMS keys." : "uses default kms keys."
        })
    });

    let isValid = resources.every(x => x.is_compliant);
    return new RuleResult({
        valid: isValid ? "success" : "fail",
        message: "No IAM policies use any Default KMS (alias/aws) keys.",
        resources
    });
};

module.exports = IAMNoPoliciesUseDefaultKMSKeys;