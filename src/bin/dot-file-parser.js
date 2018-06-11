const os = require('os');
const _ = require('lodash');

class DOTGraph {
  constructor(dotString){
    this._dotString = dotString;
    this._dict = DOTGraph.Dot2JSON(dotString);
  }

  getConnectionsFromNode(node){
    return this._dict[node] || []
  }

  static Dot2JSON(dotString){
    let graph = dotString.split(os.EOL)
      .map(x => x.trim())
      // Only get edges
      .filter(x => x.includes("->"))
      //Remove [root] and extra quotes
      .map(x => x.replace(/(\[root]|\")/g,""))
      .map( line => {
        let [from,to] = line.split("->")
        return {
          from: from.trim(),
          to: to.trim()
        }
      });

    let dict = {};

    graph.forEach(edge => {
      if(dict[edge.from])
        dict[edge.from].push(edge.to);
      else
        dict[edge.from] = [edge.to];
    });
    return dict;
  }
}

module.exports = DOTGraph;