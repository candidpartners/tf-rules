module.exports = async function GetIAMPolicyVersions({provider,additionalParams = {}}){
    try{
        let params = Object.assign({},additionalParams);
        const IAM = new provider.IAM();
        let result = await IAM.listPolicies(params).promise();
        let Policies = result.Policies || [];

        async function getPolicyVersionFromPolicy(Policy){
            let {PolicyVersion} = await IAM.getPolicyVersion({
                PolicyArn: Policy.Arn,
                VersionId: Policy.DefaultVersionId
            }).promise();

            PolicyVersion.Document = JSON.parse(decodeURIComponent(PolicyVersion.Document));
            return {
                Policy: Policy,
                PolicyVersion,
            }
        }

        let PolicyVersions = Promise.all(Policies.map(getPolicyVersionFromPolicy));
        return PolicyVersions;

    } catch(err){
        console.error("There was an error retrieving IAM Policies")
        throw err;
    }
};