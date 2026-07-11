package dev.krillin.bifrost.core.activation;

/** The two Ed25519 signatures over a SignedHead's preimage (base64). approverSig is the historical
 *  single-head signature (SignedHead.sig / signedBy=approver); activatorSig is the four-eyes co-sig
 *  (SignedHead.coSig / coSignedBy=activator). Both cover the identical preimage. */
public record HeadSignatures(String approverSig, String activatorSig) {}
