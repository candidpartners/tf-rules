module.exports = async function GetIAMCredentialReports({provider,additionalParams = {}}){
    try{
        let params = Object.assign({},additionalParams);
        const IAM = new provider.IAM();
        await IAM.generateCredentialReport();
        let report = await IAM.getCredentialReport().promise();
        let content = report.Content.toString();
        return content;

    } catch(err){
        console.error("There was an error retrieving IAM Credential Report Content")
        throw err;
    }
};