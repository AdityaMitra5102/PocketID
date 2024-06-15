from flask import *
from flask_cors import CORS
import os
import base64
import json
import pickle
import requests
app = Flask(__name__)
CORS(app)

injectjs='''
const url = 'http://localhost:5000'

function bufferToArr(buf) {
	temparr = new Uint8Array(buf);
	arr = [];
	for (i = 0; i < temparr.length; i++) {
		arr.push(temparr[i]);
	}
	return arr;
}

function arrToBuffer(arr) {
	let array = Uint8Array.from(arr);
	return array.buffer;
}

function AuthenticatorAssertionResponse(authenticatorData, clientDataJSON, signature, userHandle) {
	this.authenticatorData = authenticatorData;
	this.clientDataJSON = clientDataJSON;
	this.signature = signature;
	this.userHandle = userHandle;
}

class PublicKeyCredential {

	constructor(authenticatorAttachment, id, rawId, response, type) {
		this.authenticatorAttachment = authenticatorAttachment;
		this.id = id;
		this.rawId = rawId;
		this.response = response;
		this.type = type;
		this.clientExtensionResults={};
	}

	static async isConditionalMediationAvailable() {
		return false;
	}

	static async isUserVerifyingPlatformAuthenticatorAvailable() {
		return true;
	}

	getClientExtensionResults() {
		return {}
	}

}

var zzz;
var res1;
class cred {

	static async get(options) {
		console.log("Get called");
		console.log(options);
		const x = options;
		var rpid = encodeURIComponent(location.origin);
		zzz = options;
		const cred1 = x['publicKey']['allowCredentials']
		const chal = x['publicKey']['challenge']
		const len = cred1.length;
		var publicKey = {};
		var ac = [];
		cred1.forEach(credproc);

		function credproc(item) {
			try {
				var cr = {};
				cr['type'] = item['type']
				if ('transports' in item) {
					cr['transports'] = item['transports']
				}
				cr['id'] = bufferToArr(item['id']);
				ac.push(cr);
			} catch (err) {
				console.log(err);
			}
		}
		const challenge = bufferToArr(chal);
		var extensions = {};
		if ('extensions' in x['publicKey']) {
			const ext = x['publicKey']['extensions']
			if ('appid' in ext) {
				extensions['appid'] = ext['appid'];
			}
			publicKey['extensions'] = extensions;
		}
		const rpId = x['publicKey']['rpId'];
		const timeout = x['publicKey']['timeout'];
		const userVerification = x['publicKey']['userVerification'];
		publicKey['allowCredentials'] = ac;
		publicKey['challenge'] = challenge;
		publicKey['rpId'] = rpId;
		publicKey['timeout'] = timeout;
		publicKey['userVerification'] = userVerification;
		const tempdata = publicKey;
		console.log(tempdata);
		const response = await fetch(url + '/getoptions?site=' + rpid, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify(tempdata)
		});
		const pkcred = await response.json();
		console.log(pkcred);
		res1 = pkcred;
		const reqresp = pkcred;
		const reqrespresp = reqresp['response'];
		var aresp = {};
		aresp['authenticatorData'] = arrToBuffer(reqrespresp['authenticatorData']);
		aresp['clientDataJSON'] = arrToBuffer(reqrespresp['clientDataJSON']);
		aresp['signature'] = arrToBuffer(reqrespresp['signature']);
		if ('userHandle' in reqrespresp){
		aresp['userHandle'] = arrToBuffer(reqrespresp['userHandle']);}
		const aresp1 = new AuthenticatorAssertionResponse(aresp['authenticatorData'], aresp['clientDataJSON'], aresp['signature']);
		var finresp = {};
		finresp['authenticatorAttachment'] = reqresp['authenticatorAttachment'];
		finresp['id'] = reqresp['id'];
		finresp['rawId'] = arrToBuffer(reqresp['rawId']);
		finresp['type'] = reqresp['type'];
		finresp['response'] = aresp;
		const finr = new PublicKeyCredential(finresp['authenticatorAttachment'], finresp['id'], finresp['rawId'], aresp1, finresp['type']);
		console.log(finr);
		return Promise.resolve(finr);
	}

	static create(options) {
		console.log("create");
		console.log(options);
		
	}
}
navigator.credentials.get = cred.get;

'''




cloudurl='http://pocketid.local:5000'

def readInject():
	global txt
	#fl=open('inject.js', 'r')
	#txt=fl.read()
	#fl.close()
	#pyperclip.copy(txt)
	txt=injectjs

def arrToBarr(arr):
	x=bytearray(len(arr))
	for i in range(len(arr)):
		x[i]=arr[i]
	return bytes(x)

def makeOptions(opt):
	#print(opt)
	options={}
	options['challenge']=arrToBarr(opt['challenge'])
	options['rpId']=opt['rpId']
	if 'timeout' in opt:
		options['timeout']=opt['timeout']
	if 'userVerification' in opt:	
		options['userVerification']=opt['userVerification']
	if 'extensions' in opt:
		options['extensions']=opt['extensions']
	ac=[]
	for zz in opt['allowCredentials']:
		cred={}
		cred['type']=zz['type']
		cred['id']=arrToBarr(zz['id'])
		if 'transports' in zz:
			cred['transports']=zz['transports']
		ac.append(cred)
	options['allowCredentials']=ac
	return options		

@app.route("/", methods=["GET","POST"])
def index():
	return "active"
		
@app.route("/getoptions", methods=["GET","POST"])
def getoptions():
	opt= request.json
	url=request.args.get('site')
	options=makeOptions(opt);
	optionsb64=base64.b64encode(pickle.dumps(options)).decode()
	optdata={'optionsb64': optionsb64, 'url': url}
	optdatab64=base64.b64encode(pickle.dumps(optdata)).decode()
	print(optdata)
	resp1=requests.post(cloudurl+'/getoptions', data={'data':optdatab64})
	res1=resp1.text
	res=pickle.loads(base64.b64decode(res1.encode()))
	return jsonify(res)
	
@app.route("/get_script", methods=["GET","POST"])
def get_script():
	global txt
	return txt
		
if __name__=="__main__":
	readInject()
	app.run(host="0.0.0.0", port=5000)