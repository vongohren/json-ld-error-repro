import { sign, verify, purposes, extendContextLoader } from 'jsonld-signatures';
import { BbsBlsSignature2020, Bls12381G2KeyPair as MattrBBSKeyPair } from '@mattrglobal/jsonld-signatures-bbs';
import { Ed25519Signature2018 } from '@transmute/ed25519-signature-2018';
import { documentLoaders } from 'jsonld';
import { Bls12381G2KeyPair } from '@transmute/did-key-bls12381';
import { Ed25519KeyPair } from '@transmute/did-key-ed25519';
import { resolver } from "@transmute/did-key.js";
import VC from './vc.json';


type ProofTypes = 'Ed25519Signature2018' | 'BbsBlsSignature2020';
interface DidDocument {
  proof: {
    type: ProofTypes
  }
}

const getVerifierSuite = (didDocument: DidDocument) => {
  if(didDocument.proof.type === 'Ed25519Signature2018') {
    return new Ed25519Signature2018({});
  } 
  if(didDocument.proof.type === 'BbsBlsSignature2020') {
    console.log("Setting bbs blssignature")
    return new BbsBlsSignature2020();
  }
}

const verifyVc = async (vc) => {
  const { issuer } = vc;
  const issuerDidDoc = await resolver.resolve(issuer);
  const docLoader = (url) => {
    // when the loader requests the controller did document, return the did doument in plain
    if(url.includes(issuer)) {
      return {
        contextUrl: null, // this is for a context via a link header
        document: issuerDidDoc.didDocument,
        documentUrl: url // this is the actual context URL after redirects
      };
    }
    return documentLoaders.node()(url);
  }

  const documentLoader = extendContextLoader(docLoader);

  const suite = getVerifierSuite(vc)
  const purpose = new purposes.AssertionProofPurpose()
  let verified = await verify(vc, {
    suite,
    purpose,
    documentLoader
  });

  return verified;
}

const main = async () => {
  const signedVC = VC;
  const verifiedVC = await verifyVc(signedVC);
  console.log(verifiedVC)

};


main();
