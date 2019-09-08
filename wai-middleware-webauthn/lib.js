function WebAuthnProxy(endpoint){
  result = {};

  function getJSON(path, success, failure)
  {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function()
    {
      if (xhr.readyState === XMLHttpRequest.DONE) {
        if (xhr.status === 200) {
          success(JSON.parse(xhr.responseText));
        } else {
          failure(xhr.responseText);
        }
      }
    };
    xhr.open("GET", path, true);
    xhr.send();
  }

  function postJSON(path, body, success, failure)
  {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function()
    {
      if (xhr.readyState === XMLHttpRequest.DONE) {
        if (xhr.status === 200) {
          success(JSON.parse(xhr.responseText));
        } else {
          failure(xhr.responseText);
        }
      }
    };
    xhr.open("POST", path, true);
    xhr.send(body);
  }

  result.register = function (user, cont){
    getJSON(endpoint + "/challenge", function(challenge){
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
                [ new Uint8Array(cred.response.clientDataJSON)
                , new Uint8Array(cred.response.attestationObject)
                , new Uint8Array(rawChallenge)])
            , cont);
        })
        .catch((err) => {
          console.log("ERROR", err);
        });
    });
  };

  result.lookup = function(name, cont){
    getJSON(endpoint + "/lookup/" + name, cont)
  }
  result.verify = function(credStr, cont){
    getJSON(endpoint + "/challenge", function(challenge){
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
                , new Uint8Array(rawChallenge)])
            , cont);
        })
        .catch((err) => {
          console.log("ERROR", err);
        });
    });
  }
  return result;
}
