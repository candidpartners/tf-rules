const AWS = require('aws-sdk');
const co = require('co');
const _ = require('lodash');
const Rx = require('rxjs');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const MFAIsEnabledForIAMUsersWithConsolePassword = {};

MFAIsEnabledForIAMUsersWithConsolePassword.uuid = "0435cc47-21dc-45e3-a942-45dbef1cfb1b";
MFAIsEnabledForIAMUsersWithConsolePassword.groupName = "IAM";
MFAIsEnabledForIAMUsersWithConsolePassword.config_triggers = ["AWS::IAM::User"];
MFAIsEnabledForIAMUsersWithConsolePassword.paths = {MFAIsEnabledForIAMUsersWithConsolePassword: "aws_iam_user"};
MFAIsEnabledForIAMUsersWithConsolePassword.docs = {
    description: 'All IAM users with a console password have MFA enabled.',
    recommended: false
};
MFAIsEnabledForIAMUsersWithConsolePassword.schema = { type : 'boolean' };


MFAIsEnabledForIAMUsersWithConsolePassword.livecheck = co.wrap(function *( context ) {
    const IAM = new context.provider.IAM();

    // Get Users
    let result = yield IAM.listUsers().promise();
    let users = result.Users;

    while(result.IsTruncated){
        result = yield IAM.listUsers({Marker:result.Marker}).promise();
        users = [...users,...result.Users];
    }

    let NumberOfNonMFAUsers = yield Rx.Observable.from(users) //Get all users
        .filter(x => x.PasswordLastUsed) //filter by only those that have a password
        // .do(x => console.log(x)) //logging
        .map(user => user.UserName) //Get the username for each user
        .flatMap(UserName => Rx.Observable.fromPromise(IAM.listMFADevices({UserName}).promise())) //Get the MFA info for each user
        .map(result => result.MFADevices) // Sanitize results
        .filter(mfas => mfas.length == 0) //Get those without any MFA
        .count() //Count them
        .toPromise();

    if(NumberOfNonMFAUsers > 0){
        return {
            valid : 'fail',
            message : `There are ${NumberOfNonMFAUsers} that have a console login but don't have MFA.`
        }
    }
    else if (NumberOfNonMFAUsers == 0){
        return {
            valid: 'success'
        }
    }
});

module.exports = MFAIsEnabledForIAMUsersWithConsolePassword;
