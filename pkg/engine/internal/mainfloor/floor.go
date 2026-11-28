// Frozen copy of the protected-path check of commit 22ed838; do not edit;
// it keeps every protected-path deny of 22ed838.
//
// Every other non-test .go file in this directory is the pkg/engine file of
// commit 22ed838 with only the package clause changed. pin_test.go checks
// this with a hash of those files. The tests of 22ed838 stay in pkg/engine,
// where they test the current check. pkg/engine calls
// ViolatesProtectedPaths here whenever its own check allows a call, and
// denies whatever this denies.

package mainfloor
