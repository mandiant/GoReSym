GOLang has two concepts of 'version'. The first is for internal runtime structures,
these are usually coarse grained and named after the first version using that representation.
For example the pclntab internal structure has 3 versions, 1.2, 1.16, and 1.18. These version numbers
cover ranges of go version, >= 1.2, >= 1.16, and >= 1.18, non-overlapping. 

The second concept of 'version' is the goruntime version. This obviously changes much more frequently
than the above concept of version, and lots of internal language level features like reflection and 
type layouts may change with each runtime version. 

I've organized the structures so that most stuff is in pclntab_Go<version>, and these apply to entire ranges of go versions, but when the specific runtime version matters, the structures are labelled in specific folders labelled after the runtime Go<version>. You must consult both folders most of the time for a full listing of internal structures. If a structure appears in both folders, the specific go version takes precedant

If you look at the go source code on github, the 'master' branch is the current next unreleased go version, and there's a branch for each previously released version named like boringcrypto.go<version>.