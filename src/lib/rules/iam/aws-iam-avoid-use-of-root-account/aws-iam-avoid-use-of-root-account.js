// @flow
const Papa = require('papaparse');
const {RuleResult, Resource, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMAvoidUseOfRootAccount = {};

IAMAvoidUseOfRootAccount.uuid = "5f11d82f-4435-4973-91e8-1175698f84b6";
IAMAvoidUseOfRootAccount.groupName = "IAM";
IAMAvoidUseOfRootAccount.tags = [["CIS", "1.1.0", "1.1"]];
IAMAvoidUseOfRootAccount.config_triggers = ["AWS::IAM::User"];
IAMAvoidUseOfRootAccount.paths = {IAMAvoidUseOfRootAccount: "aws_iam_user"};
IAMAvoidUseOfRootAccount.docs = {
    description: 'The root account has not logged in in the required number of days.',
    recommended: false
};
IAMAvoidUseOfRootAccount.schema = {
    type: 'object',
    properties: {
        days: {
            type: 'number',
            title: "Number of days",
            default: 30
        }
    }
};


IAMAvoidUseOfRootAccount.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
   // const IAM = new context.provider.IAM();
    let {config, provider} = context;
    // Get credential report
    //await IAM.generateCredentialReport().promise();
    //let report = await IAM.getCredentialReport().promise();

    //let content = report.Content.toString();
    let content = await context.services.IAM.GetIAMCredentialReport({provider: context.provider, additionalParams: {}});
    // console.log(content);
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    // Get root user
    let rootUser = data.find(x => x.user === `<root_account>`);
    let {password_last_used} = rootUser;

    function getNumberOfDaysSince(date) {
        return (new Date() - date.getTime()) / (1000 * 3600 * 24)
    }

    let loginDate = new Date(password_last_used);
    let daysSinceLastUsed = getNumberOfDaysSince(loginDate);
    let RequiredDaysSinceLastUsed = config;

    let hasBeenUsedRecently = (daysSinceLastUsed <= RequiredDaysSinceLastUsed);
    return new RuleResult({
        valid: hasBeenUsedRecently ? "fail" : "success",
        message: "The root account should not be used.",
        resources: [{
            is_compliant: true,
            message: hasBeenUsedRecently ? `logged in ${daysSinceLastUsed.toFixed(0)} days ago.` : "has not been used recently.",
            resource_type: "AWS::::Account",
            resource_id: "root"
        }]
    })
};

module.exports = IAMAvoidUseOfRootAccount;

