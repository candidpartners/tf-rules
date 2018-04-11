// @flow
/*::

type valid_enum = "success" | "fail";
interface ResourceInterface{
    is_compliant: boolean,
    resource_id: string,
    resource_type: string,
    message: string,
}

interface RuleResultInterface {
    valid: valid_enum,
    message: string,
    resources: ResourceInterface[],
}
 */

class Context{
    /*:: config: any; */
    /*:: provider: any; */
    /*:: instance: any; */
}

class RuleResult{
    /*:: valid: valid_enum; */
    /*:: message: string; */
    /*:: resources: ResourceInterface[]; */

    constructor({valid,message, resources} /*: RuleResultInterface */){
        if(valid != "success" && valid != "fail")
            throw "valid must be success or fail!"
        this.valid = valid;
        this.message = message;
        this.resources = resources;
    }
}

class Resource{
    /*:: resource_id: string; */
    /*:: resource_type: string; */
    /*:: message: string */
    /*:: is_compliant: boolean */

    constructor({resource_id,resource_type,message, is_compliant} /*: ResourceInterface*/){
        this.is_compliant = is_compliant;
        this.resource_id = resource_id;
        this.resource_type = resource_type;
        this.message = message;
    }
}

module.exports = {
    RuleResult,
    Resource,
    Context
};