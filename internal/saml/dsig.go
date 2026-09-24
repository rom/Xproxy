package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// The XML Signature profile this package verifies is the narrowest one
// that still interoperates:
//
//   - Exclusive canonicalization only (with or without an
//     InclusiveNamespaces prefix list), because that is the only
//     canonicalization a SAML profile requires.
//   - Exactly one Reference per signature, whose URI is "#" followed by
//     the ID of the signature's own parent element. A signature that
//     points anywhere else is refused rather than followed.
//   - Transforms are the enveloped-signature transform and, optionally,
//     exclusive canonicalization. Nothing else: an XPath or XSLT
//     transform is a program that decides what was signed.
//   - SHA-256 and above. No SHA-1, no MD5, no HMAC (a shared key is not
//     an identity), no DSA.
//   - The key comes from the configuration, never from the document.
//     KeyInfo is not read at all, so a signature made by a key the
//     document carries is simply an unverifiable signature.
//
// Signature wrapping -- the family of attacks that hands a verifier one
// element and the consumer another -- is answered structurally rather
// than by a check: every signature in the document must verify, each
// against its own parent, and the caller may only consume elements this
// returns as signed.

var (
	// ErrSignature is a signature that does not verify, or is missing
	// where the policy requires one.
	ErrSignature = errors.New("saml: signature")
	// ErrProfile is a document this profile refuses to read.
	ErrProfile = errProfile
)

const (
	nsDSig       = "http://www.w3.org/2000/09/xmldsig#"
	algExcC14N   = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// maxSignatures bounds the signatures one document may carry. A response
// carries one on the response, one on the assertion, and that is all
// anybody needs; each one costs a canonicalization and a public key
// operation.
const maxSignatures = 4

// keyKind distinguishes the two families this package verifies, so an
// RSA key is never handed an ECDSA signature.
type keyKind uint8

const (
	keyRSA keyKind = iota + 1
	keyECDSA
)

// signatureAlg maps a SignatureMethod to its hash and key family.
func signatureAlg(uri string) (crypto.Hash, keyKind, bool) {
	switch uri {
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return crypto.SHA256, keyRSA, true
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return crypto.SHA384, keyRSA, true
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return crypto.SHA512, keyRSA, true
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
		return crypto.SHA256, keyECDSA, true
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
		return crypto.SHA384, keyECDSA, true
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
		return crypto.SHA512, keyECDSA, true
	}
	return 0, 0, false
}

// digestAlg maps a DigestMethod to its hash.
func digestAlg(uri string) (crypto.Hash, bool) {
	switch uri {
	case "http://www.w3.org/2001/04/xmlenc#sha256":
		return crypto.SHA256, true
	case "http://www.w3.org/2001/04/xmldsig-more#sha384":
		return crypto.SHA384, true
	case "http://www.w3.org/2001/04/xmlenc#sha512":
		return crypto.SHA512, true
	}
	return 0, false
}

func sum(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(b)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(b)
		return d[:]
	default:
		d := sha256.Sum256(b)
		return d[:]
	}
}

// elementIDs indexes every ID attribute in the document and refuses a
// document that uses one twice. Two elements with one ID is the oldest
// wrapping trick there is: the verifier resolves the reference to one of
// them and the consumer walks to the other.
func elementIDs(n *node, ids map[string]*node) error {
	if n.kind != kindElem {
		return nil
	}
	if id := n.attrValue("ID"); id != "" {
		if _, dup := ids[id]; dup {
			return fmt.Errorf("%w: ID %q is used by two elements", errProfile, id)
		}
		ids[id] = n
	}
	for _, k := range n.kids {
		if err := elementIDs(k, ids); err != nil {
			return err
		}
	}
	return nil
}

// verifySignatures verifies every signature in the document and returns
// the elements they cover. A document with a signature that does not
// verify is refused whole: there is no reading in which some of it is
// trustworthy and the rest is merely ignored.
func verifySignatures(doc *node, keys []crypto.PublicKey) (map[*node]bool, error) {
	var sigs []*node
	findAll(doc, nsDSig, "Signature", &sigs)
	if len(sigs) == 0 {
		return map[*node]bool{}, nil
	}
	if len(sigs) > maxSignatures {
		return nil, fmt.Errorf("%w: more than %d signatures", errProfile, maxSignatures)
	}
	ids := map[string]*node{}
	if err := elementIDs(doc, ids); err != nil {
		return nil, err
	}
	signed := map[*node]bool{}
	for _, sig := range sigs {
		target := sig.parent
		if target == nil || target.kind != kindElem {
			return nil, fmt.Errorf("%w: a signature is not enveloped in an element", errProfile)
		}
		if err := verifySignature(sig, target, ids, keys); err != nil {
			return nil, err
		}
		signed[target] = true
	}
	return signed, nil
}

// verifySignature checks one enveloped signature against its parent.
func verifySignature(sig, target *node, ids map[string]*node, keys []crypto.PublicKey) error {
	si := sig.child(nsDSig, "SignedInfo")
	sv := sig.child(nsDSig, "SignatureValue")
	if si == nil || sv == nil {
		return fmt.Errorf("%w: a signature has no SignedInfo or SignatureValue", errProfile)
	}
	cm := si.child(nsDSig, "CanonicalizationMethod")
	if cm == nil || cm.attrValue("Algorithm") != algExcC14N {
		return fmt.Errorf("%w: canonicalization method %q is not exclusive canonical XML", errProfile, cm.attrValue("Algorithm"))
	}
	sm := si.child(nsDSig, "SignatureMethod")
	hash, kind, ok := signatureAlg(sm.attrValue("Algorithm"))
	if !ok {
		return fmt.Errorf("%w: signature method %q is not accepted", errProfile, sm.attrValue("Algorithm"))
	}
	refs := si.children(nsDSig, "Reference")
	if len(refs) != 1 {
		return fmt.Errorf("%w: a signature has %d references, not one", errProfile, len(refs))
	}
	ref := refs[0]
	id := target.attrValue("ID")
	if id == "" {
		return fmt.Errorf("%w: the signed element %q has no ID", errProfile, target.qname())
	}
	if uri := ref.attrValue("URI"); uri != "#"+id {
		return fmt.Errorf("%w: reference %q does not name the element it is enveloped in", errProfile, uri)
	}
	if ids[id] != target {
		return fmt.Errorf("%w: ID %q does not resolve to the signed element", errProfile, id)
	}
	refInclusive, err := transforms(ref)
	if err != nil {
		return err
	}
	dm := ref.child(nsDSig, "DigestMethod")
	dhash, ok := digestAlg(dm.attrValue("Algorithm"))
	if !ok {
		return fmt.Errorf("%w: digest method %q is not accepted", errProfile, dm.attrValue("Algorithm"))
	}
	want, err := decodeBase64(ref.child(nsDSig, "DigestValue").chars())
	if err != nil {
		return fmt.Errorf("%w: digest value: %w", errProfile, err)
	}
	// The enveloped-signature transform is this omission: the element is
	// canonicalized without the signature that covers it, because the
	// signature cannot contain its own digest.
	canon, err := c14n(target, sig, refInclusive)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(sum(dhash, canon), want) != 1 {
		return fmt.Errorf("%w: the digest of %q does not match the signature", ErrSignature, target.qname())
	}
	siCanon, err := c14n(si, nil, prefixList(cm))
	if err != nil {
		return err
	}
	raw, err := decodeBase64(sv.chars())
	if err != nil {
		return fmt.Errorf("%w: signature value: %w", errProfile, err)
	}
	digest := sum(hash, siCanon)
	for _, key := range keys {
		if verifyWith(key, kind, hash, digest, raw) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: no configured identity provider key verifies the signature over %q", ErrSignature, target.qname())
}

// transforms checks a reference's transform list and returns the prefix
// list of its canonicalization, if it has one.
func transforms(ref *node) ([]string, error) {
	list := ref.child(nsDSig, "Transforms").children(nsDSig, "Transform")
	if len(list) == 0 || len(list) > 2 {
		return nil, fmt.Errorf("%w: a reference has %d transforms; the profile is the enveloped signature transform and optionally exclusive canonicalization", errProfile, len(list))
	}
	var inclusive []string
	seenEnveloped := false
	for i, t := range list {
		switch alg := t.attrValue("Algorithm"); alg {
		case algEnveloped:
			if i != 0 {
				return nil, fmt.Errorf("%w: the enveloped signature transform must come first", errProfile)
			}
			seenEnveloped = true
		case algExcC14N:
			if i != len(list)-1 {
				return nil, fmt.Errorf("%w: canonicalization must be the last transform", errProfile)
			}
			inclusive = prefixList(t)
		default:
			return nil, fmt.Errorf("%w: transform %q is not accepted", errProfile, alg)
		}
	}
	if !seenEnveloped {
		return nil, fmt.Errorf("%w: a reference has no enveloped signature transform", errProfile)
	}
	return inclusive, nil
}

// prefixList reads an InclusiveNamespaces PrefixList from a transform or
// canonicalization method. The prefixes it names are canonicalized as if
// every element used them, which is how a signer keeps a prefix that is
// declared outside the signed element inside the signature.
func prefixList(n *node) []string {
	inc := n.child(algExcC14N, "InclusiveNamespaces")
	if inc == nil {
		return nil
	}
	f := strings.Fields(inc.attrValue("PrefixList"))
	if len(f) > maxAttrs {
		return f[:maxAttrs]
	}
	return f
}

func verifyWith(key crypto.PublicKey, kind keyKind, hash crypto.Hash, digest, sig []byte) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if kind != keyRSA {
			return errors.New("key is RSA, signature is not")
		}
		return rsa.VerifyPKCS1v15(k, hash, digest, sig)
	case *ecdsa.PublicKey:
		if kind != keyECDSA {
			return errors.New("key is ECDSA, signature is not")
		}
		// XML Signature carries an ECDSA signature as r and s
		// concatenated at the curve's width (RFC 4051), not as the ASN.1
		// sequence the rest of the world uses.
		width := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*width {
			return errors.New("ECDSA signature is not two curve-width integers")
		}
		r := new(big.Int).SetBytes(sig[:width])
		s := new(big.Int).SetBytes(sig[width:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	default:
		return errors.New("unsupported key type")
	}
}

// decodeBase64 reads base64 that has been wrapped across lines, as XML
// signature values always are.
func decodeBase64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if clean == "" {
		return nil, errors.New("empty")
	}
	if len(clean) > 1<<16 {
		return nil, errors.New("longer than 64 KiB")
	}
	return base64.StdEncoding.DecodeString(clean)
}

// Canonical returns the Exclusive XML Canonicalization (without
// comments) of one element of doc: the element carrying this ID, or the
// document element when id is empty. With dropSignature it leaves out an
// enveloped ds:Signature child of that element, which is the form a
// signature over it covers.
//
// It is the primitive a signer needs, and it is exported for the tools
// and test providers that have to produce a signature this package will
// verify; verification itself does not go through it.
func Canonical(doc []byte, id string, dropSignature bool) ([]byte, error) {
	root, err := parseDocument(doc)
	if err != nil {
		return nil, err
	}
	target := root
	if id != "" {
		ids := map[string]*node{}
		if err := elementIDs(root, ids); err != nil {
			return nil, err
		}
		target = ids[id]
		if target == nil {
			return nil, fmt.Errorf("%w: no element carries the ID %q", errProfile, id)
		}
	}
	var omit *node
	if dropSignature {
		omit = target.child(nsDSig, "Signature")
	}
	return c14n(target, omit, nil)
}
