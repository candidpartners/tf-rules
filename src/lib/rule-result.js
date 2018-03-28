
class RuleResult{

    constructor({valid,message, noncompliant_resources}){
        if(valid != "success" && valid != "fail")
            throw "valid must be success or fail!"
        this.valid = valid;
        this.message = message;
        this.noncompliant_resources = noncompliant_resources;
    }
}

class NonCompliantResource{
    constructor({resource_id,resource_type,message}){
        this.resource_id = resource_id;
        this.resource_type = resource_type;
        this.message = message;
    }
}

module.exports = {
    RuleResult,
    NonCompliantResource
}