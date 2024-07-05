import { encrypt, decrypt, PrivateKey, PublicKey } from 'eciesjs';
import { DirectSecp256k1HdWallet, makeSignDoc } from "@cosmjs/proto-signing";
import { encodeSecp256k1Pubkey } from "@cosmjs/amino";
import { sha256 } from '@cosmjs/crypto';

const seed = ""
const chain_id = "bitsong-2b"
const fee_denom = "ubtsg"

const kp = generateKeyPair();
let aah = generateAllListenersActionsHash();
signMessage(aah, seed).then(signedMsg => {
    console.log("Signed message:", signedMsg);
}).catch(error => {
    console.error("Error signing message:", error);
});

function generateKeyPair() {
    const sk = new PrivateKey();
    console.log(sk.publicKey);
    console.log(sk.secret);

    return { publicKey: sk.publicKey, secret: sk.secret };
}

// simulates action data from 5 addrs
function generateAllListenersActionsHash() {
    const all_actions = [];
    for (let i = 0; i < 5; i++) {
        let actions = generateEncryptedActions(kp.publicKey.toHex())
        all_actions.push(actions)
    }
    console.log(all_actions)
    return base64_hash(all_actions)
}

function generateEncryptedActions(pub) {
    let hashed_actions = base64_hash(generateJsonFile());
    let encrypted_actions = encrypt_actions(pub, hashed_actions);
    return encrypted_actions
}

// generates tracked actions on file addr for one address
function generateJsonFile() {
    const actionTypes = ['a', 'b', 'c', 'd', 'e', 'f'];
    const actions = [];
    for (let i = 0; i < 5; i++) {
        const addr = [];
        for (let j = 0; j < 10; j++) {
            const actionType = actionTypes[Math.floor(Math.random() * actionTypes.length)];
            const count = Math.floor(Math.random() * 100);
            addr.push({ [actionType]: count });
        }
        actions.push({ addr });
    }
    console.log(JSON.stringify(actions))
    return JSON.stringify(actions);
}

function encrypt_actions(pub, actions) {
    console.log("encrypting hashed actions");
    const res = encrypt(pub, actions);

    return res;
}

function base64_hash(ghad) {
    console.log("hashing actions");
    const jsonString = JSON.stringify(ghad);
    const encoded = Buffer.from(jsonString).toString('base64');
    return encoded;
}

// sign AEA with key 
async function signMessage(msg, mnemonic) {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic);
    const accounts = await wallet.getAccounts();
    const signer = accounts[0].address;

    // encode to bytes
    const messageBytes = Buffer.from(msg, 'base64');
    // sha256sum messageBytes
    const hash = await sha256(messageBytes);

    const signDoc = makeSignDoc(
        messageBytes,
        Buffer.from(
            JSON.stringify({
                fee: {
                    amount: [{ denom: fee_denom, amount: '1' }],
                    gas: '200000',
                },
                signer_infos: [{
                    public_key: {
                        type: 'tendermint/PubKeySecp256k1',
                        value: encodeSecp256k1Pubkey(accounts[0].pubkey)
                    },
                    mode_info: { single: { mode: 'SIGN_MODE_LEGACY_AMINO_JSON' } },
                    sequence: 1,
                }]
            }), 'utf8'
        ),
        chain_id,
        1
    );

    // sign with key
    const signed = await wallet.signDirect(signer, signDoc);
    return { signed, hash };
}