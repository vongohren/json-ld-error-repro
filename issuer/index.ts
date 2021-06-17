import { sign, verify, purposes, extendContextLoader } from 'jsonld-signatures';
import { BbsBlsSignature2020, Bls12381G2KeyPair as MattrBBSKeyPair } from '@mattrglobal/jsonld-signatures-bbs';
import { Ed25519Signature2018 } from '@transmute/ed25519-signature-2018';
import { documentLoaders } from 'jsonld';
import { Bls12381G2KeyPair } from '@transmute/did-key-bls12381';
import { Ed25519KeyPair } from '@transmute/did-key-ed25519';
import EmailCredential from './email.json';
import BBSKey from './key.json';

export type Key = {
  did: string;
  key: string;
};

export type DidTypes = 'did:key';

export type DIDKeyTypes = 'Bls12381G2Key2020' | 'Ed25519VerificationKey2018';
export type SupportedKeyPairs = Bls12381G2KeyPair | Ed25519KeyPair;
export interface KeyPair {
  id: string;
  type: DIDKeyTypes;
  controller: string;
  publicKeyBase58: string;
  privateKeyBase58: string;
}


const getSignerSuite = async (key: SupportedKeyPairs) => {
  if(key instanceof Bls12381G2KeyPair) {
    const keyPair = key.toKeyPair(true);
    const recontstructedKey = await MattrBBSKeyPair.from(keyPair);
    return new BbsBlsSignature2020({ key: recontstructedKey })
  } 
  if(key instanceof Ed25519KeyPair) return new Ed25519Signature2018({ key })
}

const createVc = async () => {
  const key = await Bls12381G2KeyPair.from(BBSKey);
  const signableTemplate = EmailCredential

  const docLoader = (url) => {
    //If you want too see the url that is loaded uncomment this
    //Its worth considering caching contextes that we use alot, to speed up things
    //Ref: https://github.com/mattrglobal/jsonld-signatures-bbs/issues/115
    // console.log(url)
    return documentLoaders.node()(url);
  }
    
  const documentLoader = extendContextLoader(docLoader);
  const suite = <any>await getSignerSuite(key);
  const purpose = new purposes.AssertionProofPurpose();

  const signedDocument = await sign(signableTemplate, {
    suite,
    purpose,
    documentLoader
  });
  
  return signedDocument;
}

const main = async () => {
  const signedVC = await createVc();
  console.log(JSON.stringify(signedVC))

};


main();
