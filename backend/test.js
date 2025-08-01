const { Issuer } = require('openid-client');

async function test() {
  try {
    const issuer = await Issuer.discover('https://jp-osa.appid.cloud.ibm.com/oauth/v4/ba920c0d-1f13-4528-8aa6-dda3b2b043c9/.well-known/openid-configuration');
    console.log('Issuer discovered:', issuer.issuer);
  } catch (err) {
    console.error('Error:', err);
  }
}

test();
