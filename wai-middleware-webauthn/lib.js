function WebAuthnProxy(endpoint){
  result = {};

  function getJSON(path)
  {
    return new Promise(function(resolve, reject){
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function()
      {
        if (xhr.readyState === XMLHttpRequest.DONE) {
          if (xhr.status === 200) {
            resolve(JSON.parse(xhr.responseText));
          } else {
            reject(xhr.responseText);
          }
        }
      };
      xhr.open("GET", path, true);
      xhr.send();
    });
  }

  function postJSON(path, body)
  {
    return new Promise(function(resolve, reject){
      var xhr = new XMLHttpRequest();
      xhr.onreadystatechange = function()
      {
        if (xhr.readyState === XMLHttpRequest.DONE) {
          if (xhr.status === 200) {
            resolve(JSON.parse(xhr.responseText));
          } else {
            reject(xhr.responseText);
          }
        }
      };
      xhr.open("POST", path, true);
      xhr.send(body);
    });
  }

  result.register = user => new Promise(function(resolve, reject){
    getJSON(endpoint + "/challenge").then(function(challenge){
      let rawChallenge = base64js.toByteArray(challenge);
      let info =
          { challenge: rawChallenge
          , user: user
          , timeout: 60000
          , rp: {name: "localhost"}
          , pubKeyCredParams:
            [{ type: "public-key"
            , alg: -7
            }]
          , attestation: "direct"};
      navigator.credentials.create({publicKey: info})
        .then((cred) => {
          postJSON(endpoint + "/register"
            , CBOR.encode(
                [ user
                , new Uint8Array(cred.response.clientDataJSON)
                , new Uint8Array(cred.response.attestationObject)
                , new Uint8Array(rawChallenge)])).then(resolve).catch(reject);
        })
        .catch((err) => reject(err));
    })});

  result.lookup = name => getJSON(endpoint + "/lookup/" + name);

  result.verify = credStr => new Promise(function(resolve, reject){
    getJSON(endpoint + "/challenge").then(function(challenge){
      let rawChallenge = base64js.toByteArray(challenge);
      let credId = base64js.toByteArray((credStr + '==='.slice((credStr.length + 3) % 4))
          .replace(/-/g, '+')
          .replace(/_/g, '/'));
      navigator.credentials.get({publicKey:
        { challenge: rawChallenge
        , allowCredentials:
          [ { type: "public-key", id: credId, transports: ["usb", "nfc", "ble", "internal"] }]
        , timeout: 60000
        }})
        .then((cred) => {
          postJSON(endpoint + "/verify"
            , CBOR.encode(
                [ credId
                , new Uint8Array(cred.response.clientDataJSON)
                , new Uint8Array(cred.response.authenticatorData)
                , new Uint8Array(cred.response.signature)
                , new Uint8Array(rawChallenge)])).then(resolve).catch(reject);
        })
        .catch(reject);
    })});
  return result;
}
