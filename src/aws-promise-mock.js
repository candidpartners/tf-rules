class MockAWS{

    Service(service, method, result){
        if(!this[service]){
            this[service] = function(){}
        }
        this[service].prototype[method] = function (){
            return {
                promise: () => Promise.resolve(result)
            }
        }
    }

    ServiceError(service, method, error){
        if(!this[service]){
            this[service] = function(){}
        }
        this[service].prototype[method] = function (){
            return {
                promise: () => Promise.reject(error)
            }
        }
    }
}

module.exports = MockAWS;