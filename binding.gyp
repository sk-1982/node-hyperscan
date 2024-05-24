{
  'targets': [
    {
      'target_name': 'hyperscan',
      'sources': [ 'src/addon.cc', 'src/Hyperscan.cc' ],
      'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")", "<!(node -p \"require('./config.json').hyperscan_include\")", "./src"],
	  'libraries': ["<!(node -p \"require('./config.json').hyperscan_lib\")", "<!(node -p \"require('./config.json').hyperscan_runtime_lib\")"],
      'dependencies': [
      ],
	  'defines': ['NAPI_DISABLE_CPP_EXCEPTIONS']
    }
  ]
}