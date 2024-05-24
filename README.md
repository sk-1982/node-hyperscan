This is a Node.js binding for Intel's [Hyperscan](https://github.com/intel/hyperscan) regular expression library,
which allows for fast regular expression matching.

### Usage
`HyperscanPattern` is exported by this package, which allows for constructing Hyperscan patterns.
This is designed to be a mostly drop-in replacement for `RegExp`, with some [additional limitations imposed by Hyperscan](https://intel.github.io/hyperscan/dev-reference/compilation.html#pattern-support)

#### Examples
```js
const { HyperscanPattern } = require('.');
const pattern1 = new HyperscanPattern('a+', 'ig');
const pattern2 = new HyperscanPattern(/abc/ig);

console.log('abcabc'.replace(pattern2, 'test')); // "testtest"
console.log('aaa a aaaaa aa'.replace(pattern1, match => match.length)) // "3 1 5 2"
```


### Building
You will need to build hyperscan normally, and then set its paths in config.json (see config.example.json)

Then, rurn `node-gyp configure` and `node-gyp build`



