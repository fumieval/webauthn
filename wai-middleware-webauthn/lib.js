function WebAuthnProxy(hostName, endpoint){
  function unescape (str) {
    return (str + '==='.slice((str.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/')
  }

  function escape (str) {
    return str.replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
  }

  base64 = {
    encode: function(str, encoding) {
      return escape(buffer.Buffer.from(str, encoding || 'utf8').toString('base64'))
    },
    decode: function(str, encoding) {
      return buffer.Buffer.from(unescape(str), 'base64').buffer
    }
  }
  result = {};

  result.register = user => new Promise(function(resolve, reject){
    fetch(endpoint + "/challenge")
    .then(resp => resp.json())
    .then(function(challenge){
      let rawChallenge = base64.decode(challenge);
      let info =
          { challenge: rawChallenge
          , user: user
          , timeout: 60000
          , rp: {name: hostName}
          , pubKeyCredParams:
            [{ type: "public-key"
            , alg: -7
            }
            ,{ type: "public-key"
            , alg: -257
            }]
          , attestation: "direct"};
      navigator.credentials.create({publicKey: info})
        .then((cred) => {
          fetch(endpoint + "/register", {
            method: 'POST',
            body: JSON.stringify({
              challenge: challenge,
              user: {
                id: base64.encode(user.id),
                displayName: user.displayName
              },
              response: {
                attestationObject: base64.encode(cred.response.attestationObject),
                clientDataJSON: base64.encode(cred.response.clientDataJSON),
                transports: cred.response.transports
              },
            })
          }).then(resolve).catch(reject);
        })
        .catch(reject);
    })});

  result.lookup = name => fetch(endpoint + "/lookup/" + name).then(resp => resp.json());

  result.verify = credStr => new Promise(function(resolve, reject){
    fetch(endpoint + "/challenge")
    .then(response => response.json())
    .then(function(challenge){
      let rawChallenge = base64.decode(challenge);
      let credId = base64.decode(credStr);
      navigator.credentials.get({publicKey:
        { challenge: rawChallenge
        , allowCredentials:
          [ { type: "public-key", id: credId, transports: ["usb", "nfc", "ble", "internal"] }]
        , timeout: 60000
        }})
        .then((cred) => {
          fetch(endpoint + "/verify", {
            method: "POST",
            body: JSON.stringify(
              { credential:
                {
                  id: cred.id,
                  rawId: base64.encode(cred.rawId),
                  type: cred.type,
                  response: {
                    authenticatorData: base64.encode(cred.response.authenticatorData),
                    clientDataJSON: base64.encode(cred.response.clientDataJSON),
                    signature: base64.encode(cred.response.signature),
                  }
                }
              , challenge: challenge
              })
          }).then(resolve).catch(reject);
        })
        .catch(reject);
    })});
  return result;
}
