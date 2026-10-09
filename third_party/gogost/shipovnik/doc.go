// Package shipovnik implements the experimental code-based Shipovnik digital
// signature scheme described by QAPP and in the TSU publication.
//
// The package deliberately exposes only two fixed parameter sets. Reference is
// the current QAPP profile with 219 rounds. Article70 is the historical,
// research-only 70-bit example with 137 rounds; applications must not silently
// downgrade to it. Raw keys do not encode a profile identifier, so callers must
// never import the same raw key under different schemes.
package shipovnik
