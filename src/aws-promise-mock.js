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
}

module.exports = MockAWS;