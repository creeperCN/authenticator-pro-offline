var password;
var iterations, salt, iv;
var payload;


var decrypted_content;
var decrypted_content_pretty;
var tokens = [{
  'label': "Demo",
  'token': null,
  'totp': new OTPAuth.TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromB32(stripSpaces("THISISATEST")),
  }),
  'digits': 6,
  'period': 30,
  'updatingIn': 0,
  'icon': 'default'
}];
let header_length = 16;
let tag_length = 16;
let salt_length = 16;
let legacy_salt_length = 20;
let iv_length = 12;
let legacy_iv_length = 16;
let legacy = false;

function showQR(index) {
  var qrcode = new QRCode(document.getElementById("qrcode"), {
    text: "init",
    width : 256,
    height : 256,
    useSVG: true
  });

  var obj = JSON.parse(decrypted_content)['Authenticators'][index];
  
  var url = `otpauth://totp/${obj.Issuer}:${obj.Label}?secret=${obj.Secret}&issuer=${obj.Issuer}&algorithm=${obj.Algorithm}&digits=${obj.Digits}&period=${obj.Period}`;
  document.getElementById("qrModal").classList.add("is-active")
  url = encodeURI(url)
  qrcode.makeCode(url.toString());
  //document.getElementById("qrCode").src = qrcode;
};

function closeModal() {
  document.getElementById("qrModal").classList.remove("is-active")
}

function getCurrentSeconds() {
  return Math.round(new Date().getTime() / 1000.0);
}

function stripSpaces(str) {
  return str.replace(/\s/g, '');
}

function truncateTo(str, digits) {
  if (str.length <= digits) {
    return str;
  }

  return str.slice(-digits);
}

Vue.component('otp-entry', {
  props: ['item', 'index'],
  template: `
  <div class="box">
    <span class="has-text-grey is-size-7">Updating in {{ item.updatingIn }} seconds</span>
    <progress class="progress is-info is-small" v-bind:value="item.period - item.updatingIn" :max="item.period"></progress>
    <div class="columns is-vcentered is-mobile">
      <div  class="column is-narrow is-flex is-vcentered">
        <img style="width: 32px" v-bind:src="'https://github.com/jamie-mh/AuthenticatorPro/raw/master/icons/' + item.icon + '.png'">
      </div>
      <div class="column">
        <p class="title is-size-3 is-pulled-left">{{ item.label }}</p>
      </div>
      <div class="column" @click="showQR(index)">
        <code class="title is-size-3 is-pulled-right">{{ item.token }}</code>
      </div>
    </div>
  </div>
  `
})

new Vue({
  el: '#app',
  data: {
    token: null,
    period: 30,
    updatingIn: 0,
    tokens: tokens
  },

  mounted: function () {
    this.getKeyFromUrl();
    this.update();

    this.intervalHandle = setInterval(this.update, 1000);
  },

  destroyed: function () {
    clearInterval(this.intervalHandle);
  },

  methods: {
    update: function () {
      for (i = 0; i < this.tokens.length; i++) {
        Vue.set(this.tokens[i], 'token', truncateTo(this.tokens[i].totp.generate(), this.tokens[i].digits));
        Vue.set(this.tokens[i], 'updatingIn', this.tokens[i].period - (getCurrentSeconds() % this.tokens[i].period));
      }
    },

    getKeyFromUrl: function () {
      const key = document.location.hash.replace(/[#\/]+/, '');

      if (key.length > 0) {
        this.secret_key = key;
      }
    },
  }
});


function openFile(event) {
    var input = event.target;

    var reader = new FileReader();
    reader.onload = function() {
        var arrayBuffer = reader.result;
        
        // Javas ByteBuffer is Big Endian by default,
        // we need to consider this
        header = arrayBuffer.slice(0, header_length)
        console.log(new TextDecoder().decode(header))
        if (new TextDecoder().decode(header) == "AuthenticatorPro") {
          console.log("Legacy");
          legacy = true;
          salt = new Uint8Array(arrayBuffer.slice(header_length, header_length + legacy_salt_length));
          iv = arrayBuffer.slice(header_length + legacy_salt_length, header_length + legacy_salt_length + legacy_iv_length);
          payload = arrayBuffer.slice(header_length + legacy_salt_length + legacy_iv_length);
        } else if (new TextDecoder().decode(header) == "AUTHENTICATORPRO") {
          console.log("Strong");
          salt = new Uint8Array(arrayBuffer.slice(header_length, header_length + salt_length));
          iv = arrayBuffer.slice(header_length + salt_length, header_length + salt_length + iv_length);
          payload = arrayBuffer.slice(header_length + salt_length + iv_length);
        }
        
        document.getElementById("iptPassword").disabled = false;
        document.getElementById("btnDecrypt").disabled = false;
    };
    reader.readAsArrayBuffer(input.files[0]);
};

async function decrypt() {
    var pw = document.getElementById("iptPassword");
    password = pw.value;
    var encryptionType;
    if (legacy) {
      encryptionType = "AES-CBC";
      let keyMaterial = await getKeyMaterial();
      var key = await window.crypto.subtle.deriveKey(
          {
              "name": "PBKDF2",
              salt: salt,
              "iterations": 64000,
              "hash": "SHA-1"
          },
          keyMaterial,
          { "name": "AES-CBC", "length": 256 },
          false,
          [ "decrypt" ]
      );
    } else {
      encryptionType = "AES-GCM";
      var key = await argon2
      .hash({
          pass: password,
          salt: salt,
          time: 3,
          raw: true,
          parallelism: 4,
          hashLen: 32,
          mem: 65536,
          type: argon2.ArgonType.Argon2id
      })
      key = await window.crypto.subtle.importKey("raw", key.hash, 'AES-GCM', true, ["decrypt"]);
    } 
    let decryptSuccess = true;
    let decrypted = await window.crypto.subtle.decrypt(
        {
            name: encryptionType,
            iv: iv
        },
        key,
        payload
    )
    .catch(function(err) {
        console.error(err);
        decryptSuccess = false;
    })
    if (decryptSuccess) {
        document.getElementById("iptPassword").classList.remove("is-danger")
        document.getElementById("iptPassword").classList.add("is-primary")
        decrypted_content = new TextDecoder("utf-8").decode(new Uint8Array(decrypted));
        addToken(decrypted_content);
        document.getElementById("json_box").innerText = JSON.stringify(JSON.parse(decrypted_content), undefined, 2);
        document.getElementById("btnDownload").disabled = false;
        document.getElementById("btnShow").disabled = false;
    } else {
        tokens.splice(0,tokens.length);
        document.getElementById("iptPassword").classList.remove("is-primary")
        document.getElementById("iptPassword").classList.add("is-danger")

        //document.getElementById("content").innerText = ""
        document.getElementById("btnDownload").disabled = true;
        document.getElementById("btnShow").disabled = true;

        //window.alert("Decryption failed, please check your password!");
    }
};

function toggleContent() {
    let contentDiv = document.getElementById("content");

    if (contentDiv.style.display === "none") {
        contentDiv.style.display = "block";
    } else if (contentDiv.style.display === "block") {
        contentDiv.style.display = "none";
    }
}


function downloadPlain() {
    data_uri = "data:text/json;charset=utf-8," + encodeURIComponent(decrypted_content, undefined, 2);

    var element = document.createElement("a");
    element.setAttribute("href", data_uri);
    element.setAttribute("download", "andOTP_Backup.json");

    element.style.display = "none";

    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

function getKeyMaterial() {
    let enc = new TextEncoder();

    return window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        [ "deriveBits", "deriveKey" ]
    );
}

function loadHandler() {
    document.getElementById("content").innerText = "";
    document.getElementById("content").style.display = "none";
    document.getElementById("iptFile").value = "";
    document.getElementById("iptPassword").disabled = true;
    document.getElementById("btnDecrypt").disabled = true;
    document.getElementById("btnDownload").disabled = true;
    document.getElementById("btnShow").disabled = true;
}

function addToken(decrypted_content) {
  decrypted_content = JSON.parse(decrypted_content)['Authenticators']
  tokens.length = 0;
  for(i=0; i < decrypted_content.length; i++) {
    item = decrypted_content[i]
    if (item.Type != 2) {
      continue
    }
    tokens.push({
      'label': `${item.Issuer}: ${item.Username}`,
      'token': null,
      'totp': new OTPAuth.TOTP({
        algorithm: 'SHA1',
        digits: item.Digits,
        period: item.Period,
        secret: OTPAuth.Secret.fromB32(stripSpaces(item.Secret.replace(/\W/g, ''))),
      }),
      'digits': item.Digits,
      'period': item.Period,
      'icon': (item.Icon == undefined) ? "default": item.Icon,
      'updatingIn': 0
    });;
  }
}