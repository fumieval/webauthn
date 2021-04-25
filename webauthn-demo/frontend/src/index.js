import axios from 'axios'
import * as webauthn from '@github/webauthn-json'

async function register(username) {
  const options = (await axios.post(`/webauthn/credentialCreationOptions?username=${username}`)).data
  const credential = await webauthn.create({ publicKey: options, })
  const result = (await axios.post(`/webauthn/registerCredential?username=${username}`, credential)).data
  return { options, credential, result }
}

async function login(username) {
  const options = (await axios.post(`/webauthn/credentialRequestOptions?username=${username}`)).data
  const credential = await webauthn.get({ publicKey: options, })
  const result = (await axios.post(`/webauthn/verifyCredential?username=${username}`, credential)).data
  return { options, credential, result }
}

function log({title, text}) {
  const out = document.querySelector('#output')
  out.textContent += `# ${title}:\n`
  out.textContent += text
  out.textContent += '\n\n'
}

function scrollToBottom() {
  const out = document.querySelector('#output')
  out.scroll({top: out.scrollHeight, behavior: 'smooth'})
}

window.addEventListener('load', () => {

  document.querySelector('#supported').textContent = webauthn.supported()
    ? " ✅"
    : " ❌";

  document.querySelector('#btn-clear').addEventListener('click', () => {
    document.querySelector('#output').textContent = ''
  })

  document.querySelector('#btn-register').addEventListener('click', () => {
    if (!document.querySelector('#form').reportValidity()) {
      return
    }
  
    const username = document.querySelector('#username').value

    register(username)
      .then(res => {
        const msgs = [
          {
            title: 'PublicKeyCredentialCreationOptions',
            text: JSON.stringify(res.options, null, 2),
          },
          {
            title: 'PublicKeyCredential AuthenticatorAttestationResponse',
            text: JSON.stringify(res.credential, null, 2),
          },
          {
            title: 'Registration result',
            text: JSON.stringify(res.result, null, 2),
          },
        ]
        msgs.map(log)
        scrollToBottom()
      })
      .catch(err => {
        console.log(err)
        if (!!err.response) {
          log({ title: 'Error from server', text: JSON.stringify(err.response.data, null, 2) })
        } else {
          log({ title: 'Error', text: JSON.stringify(err, null, 2) })
        }
        scrollToBottom()
      })
  })

  document.querySelector('#btn-login').addEventListener('click', () => {
    if (!document.querySelector('#form').reportValidity()) {
      return
    }
  
    const username = document.querySelector('#username').value

    login(username)
      .then(res => {
        const msgs = [
          {
            title: 'PublicKeyCredentialRequestOptions',
            text: JSON.stringify(res.options, null, 2),
          },
          {
            title: 'PublicKeyCredential AuthenticatorAssertionResponse',
            text: JSON.stringify(res.credential, null, 2),
          },
          {
            title: 'Login result',
            text: JSON.stringify(res.result, null, 2),
          },
        ]
        msgs.map(log)
        scrollToBottom()
      })
      .catch(err => {
        console.log(err)
        if (!!err.response) {
          log({ title: 'Error from server', text: JSON.stringify(err.response.data, null, 2) })
        } else {
          log({ title: 'Error', text: JSON.stringify(err, null, 2) })
        }
        scrollToBottom()
      })
  })
})
