const { assignDefaults } = require('./_utils')

module.exports = function auth0 (strategy) {
  assignDefaults(strategy, {
    _scheme: 'auth0',
    authorization_endpoint: `https://${strategy.domain}/login`,
    userinfo_endpoint: `https://${strategy.domain}/userinfo`,
    scope: ['openid', 'profile', 'email'],
    audience: `${strategy.audience}`,
  })
}
