const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = {
  entry: './index.js',
  target: 'node',
  mode: 'production',
  externals: [
    nodeExternals({
      allowlist: [
        '@vendia/serverless-express',
        'serverless-http'
      ]
    })
  ],
  output: {
    libraryTarget: 'commonjs2',
    path: path.resolve(__dirname, '.webpack'),
    filename: 'index.js',
  },
  resolve: {
    extensions: ['.js', '.json'],
  },
  optimization: {
    minimize: false,
  },
  stats: 'minimal',
};
