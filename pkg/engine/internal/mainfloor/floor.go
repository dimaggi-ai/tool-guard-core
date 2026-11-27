// Frozen copy of v0.8.x protected-path rules; do not edit; it guarantees
// main's denies.
//
// Every other .go file in this directory is the pkg/engine file of commit
// 22ed838 with only the package clause changed, and in the tests also the
// import path of the package and the relative paths to the repository
// files, which are two directories further up. pkg/engine calls
// ViolatesProtectedPaths here whenever its own check allows a call, and
// denies whatever this denies.

package mainfloor
