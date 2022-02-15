package main

var standardPackages = []string{"archive", "archive/tar", "archive/tar/testdata", "archive/zip", "archive/zip/testdata", "bufio", "builtin", "bytes", "cmd", "cmd/addr2line", "cmd/api", "cmd/api/testdata", "cmd/api/testdata/src", "cmd/api/testdata/src/issue21181", "cmd/api/testdata/src/issue21181/dep", "cmd/api/testdata/src/issue21181/indirect", "cmd/api/testdata/src/issue21181/p", "cmd/api/testdata/src/issue29837", "cmd/api/testdata/src/issue29837/p", "cmd/api/testdata/src/pkg", "cmd/api/testdata/src/pkg/p1", "cmd/api/testdata/src/pkg/p2", "cmd/api/testdata/src/pkg/p3", "cmd/api/testdata/src/pkg/p4", "cmd/asm", "cmd/asm/internal", "cmd/asm/internal/arch", "cmd/asm/internal/asm", "cmd/asm/internal/asm/testdata", "cmd/asm/internal/asm/testdata/avx512enc", "cmd/asm/internal/flags", "cmd/asm/internal/lex", "cmd/buildid", "cmd/cgo", "cmd/compile", "cmd/compile/internal", "cmd/compile/internal/abi", "cmd/compile/internal/amd64", "cmd/compile/internal/arm", "cmd/compile/internal/arm64", "cmd/compile/internal/base", "cmd/compile/internal/bitvec", "cmd/compile/internal/deadcode", "cmd/compile/internal/devirtualize", "cmd/compile/internal/dwarfgen", "cmd/compile/internal/escape", "cmd/compile/internal/gc", "cmd/compile/internal/importer", "cmd/compile/internal/importer/testdata", "cmd/compile/internal/importer/testdata/versions", "cmd/compile/internal/inline", "cmd/compile/internal/ir", "cmd/compile/internal/liveness", "cmd/compile/internal/logopt", "cmd/compile/internal/mips", "cmd/compile/internal/mips64", "cmd/compile/internal/noder", "cmd/compile/internal/objw", "cmd/compile/internal/pkginit", "cmd/compile/internal/ppc64", "cmd/compile/internal/reflectdata", "cmd/compile/internal/riscv64", "cmd/compile/internal/s390x", "cmd/compile/internal/ssa", "cmd/compile/internal/ssa/gen", "cmd/compile/internal/ssa/testdata", "cmd/compile/internal/ssagen", "cmd/compile/internal/staticdata", "cmd/compile/internal/staticinit", "cmd/compile/internal/syntax", "cmd/compile/internal/syntax/testdata", "cmd/compile/internal/syntax/testdata/go2", "cmd/compile/internal/test", "cmd/compile/internal/test/testdata", "cmd/compile/internal/test/testdata/gen", "cmd/compile/internal/test/testdata/mysort", "cmd/compile/internal/test/testdata/reproducible", "cmd/compile/internal/typebits", "cmd/compile/internal/typecheck", "cmd/compile/internal/typecheck/builtin", "cmd/compile/internal/types", "cmd/compile/internal/types2", "cmd/compile/internal/types2/testdata", "cmd/compile/internal/types2/testdata/check", "cmd/compile/internal/types2/testdata/check/decls2", "cmd/compile/internal/types2/testdata/check/importdecl0", "cmd/compile/internal/types2/testdata/check/importdecl1", "cmd/compile/internal/types2/testdata/check/issue25008", "cmd/compile/internal/types2/testdata/examples", "cmd/compile/internal/types2/testdata/fixedbugs", "cmd/compile/internal/types2/testdata/spec", "cmd/compile/internal/walk", "cmd/compile/internal/wasm", "cmd/compile/internal/x86", "cmd/cover", "cmd/cover/testdata", "cmd/cover/testdata/html", "cmd/dist", "cmd/doc", "cmd/doc/testdata", "cmd/doc/testdata/merge", "cmd/doc/testdata/nested", "cmd/doc/testdata/nested/empty", "cmd/doc/testdata/nested/nested", "cmd/fix", "cmd/go", "cmd/go/internal", "cmd/go/internal/auth", "cmd/go/internal/base", "cmd/go/internal/bug", "cmd/go/internal/cache", "cmd/go/internal/cfg", "cmd/go/internal/clean", "cmd/go/internal/cmdflag", "cmd/go/internal/doc", "cmd/go/internal/envcmd", "cmd/go/internal/fix", "cmd/go/internal/fmtcmd", "cmd/go/internal/fsys", "cmd/go/internal/generate", "cmd/go/internal/get", "cmd/go/internal/help", "cmd/go/internal/imports", "cmd/go/internal/imports/testdata", "cmd/go/internal/imports/testdata/android", "cmd/go/internal/imports/testdata/illumos", "cmd/go/internal/imports/testdata/star", "cmd/go/internal/list", "cmd/go/internal/load", "cmd/go/internal/lockedfile", "cmd/go/internal/lockedfile/internal", "cmd/go/internal/lockedfile/internal/filelock", "cmd/go/internal/modcmd", "cmd/go/internal/modconv", "cmd/go/internal/modconv/testdata", "cmd/go/internal/modfetch", "cmd/go/internal/modfetch/codehost", "cmd/go/internal/modfetch/zip_sum_test", "cmd/go/internal/modfetch/zip_sum_test/testdata", "cmd/go/internal/modget", "cmd/go/internal/modinfo", "cmd/go/internal/modload", "cmd/go/internal/mvs", "cmd/go/internal/par", "cmd/go/internal/robustio", "cmd/go/internal/run", "cmd/go/internal/search", "cmd/go/internal/str", "cmd/go/internal/test", "cmd/go/internal/test/internal", "cmd/go/internal/test/internal/genflags", "cmd/go/internal/tool", "cmd/go/internal/trace", "cmd/go/internal/vcs", "cmd/go/internal/version", "cmd/go/internal/vet", "cmd/go/internal/web", "cmd/go/internal/work", "cmd/go/internal/workcmd", "cmd/go/testdata", "cmd/go/testdata/failssh", "cmd/go/testdata/mod", "cmd/go/testdata/modlegacy", "cmd/go/testdata/modlegacy/src", "cmd/go/testdata/modlegacy/src/new", "cmd/go/testdata/modlegacy/src/new/p1", "cmd/go/testdata/modlegacy/src/new/p2", "cmd/go/testdata/modlegacy/src/new/sub", "cmd/go/testdata/modlegacy/src/new/sub/inner", "cmd/go/testdata/modlegacy/src/new/sub/inner/x", "cmd/go/testdata/modlegacy/src/new/sub/x", "cmd/go/testdata/modlegacy/src/new/sub/x/v1", "cmd/go/testdata/modlegacy/src/new/sub/x/v1/y", "cmd/go/testdata/modlegacy/src/old", "cmd/go/testdata/modlegacy/src/old/p1", "cmd/go/testdata/modlegacy/src/old/p2", "cmd/go/testdata/script", "cmd/go/testdata/testterminal18153", "cmd/gofmt", "cmd/gofmt/testdata", "cmd/internal", "cmd/internal/archive", "cmd/internal/archive/testdata", "cmd/internal/archive/testdata/mycgo", "cmd/internal/bio", "cmd/internal/browser", "cmd/internal/buildid", "cmd/internal/buildid/testdata", "cmd/internal/codesign", "cmd/internal/diff", "cmd/internal/dwarf", "cmd/internal/edit", "cmd/internal/gcprog", "cmd/internal/goobj", "cmd/internal/moddeps", "cmd/internal/obj", "cmd/internal/obj/arm", "cmd/internal/obj/arm64", "cmd/internal/obj/mips", "cmd/internal/obj/ppc64", "cmd/internal/obj/riscv", "cmd/internal/obj/riscv/testdata", "cmd/internal/obj/riscv/testdata/testbranch", "cmd/internal/obj/s390x", "cmd/internal/obj/wasm", "cmd/internal/obj/x86", "cmd/internal/objabi", "cmd/internal/objfile", "cmd/internal/pkgpath", "cmd/internal/quoted", "cmd/internal/src", "cmd/internal/sys", "cmd/internal/test2json", "cmd/internal/test2json/testdata", "cmd/internal/traceviewer", "cmd/link", "cmd/link/internal", "cmd/link/internal/amd64", "cmd/link/internal/arm", "cmd/link/internal/arm64", "cmd/link/internal/benchmark", "cmd/link/internal/dwtest", "cmd/link/internal/ld", "cmd/link/internal/ld/testdata", "cmd/link/internal/ld/testdata/deadcode", "cmd/link/internal/ld/testdata/httptest", "cmd/link/internal/ld/testdata/httptest/main", "cmd/link/internal/ld/testdata/issue10978", "cmd/link/internal/ld/testdata/issue25459", "cmd/link/internal/ld/testdata/issue25459/a", "cmd/link/internal/ld/testdata/issue25459/main", "cmd/link/internal/ld/testdata/issue26237", "cmd/link/internal/ld/testdata/issue26237/b.dir", "cmd/link/internal/ld/testdata/issue26237/main", "cmd/link/internal/ld/testdata/issue32233", "cmd/link/internal/ld/testdata/issue32233/lib", "cmd/link/internal/ld/testdata/issue32233/main", "cmd/link/internal/ld/testdata/issue38192", "cmd/link/internal/ld/testdata/issue39256", "cmd/link/internal/ld/testdata/issue39757", "cmd/link/internal/ld/testdata/issue42484", "cmd/link/internal/loadelf", "cmd/link/internal/loader", "cmd/link/internal/loadmacho", "cmd/link/internal/loadpe", "cmd/link/internal/loadxcoff", "cmd/link/internal/mips", "cmd/link/internal/mips64", "cmd/link/internal/ppc64", "cmd/link/internal/riscv64", "cmd/link/internal/s390x", "cmd/link/internal/sym", "cmd/link/internal/wasm", "cmd/link/internal/x86", "cmd/link/testdata", "cmd/link/testdata/pe-binutils", "cmd/link/testdata/pe-llvm", "cmd/link/testdata/testBuildFortvOS", "cmd/link/testdata/testHashedSyms", "cmd/link/testdata/testIndexMismatch", "cmd/link/testdata/testRO", "cmd/nm", "cmd/objdump", "cmd/objdump/testdata", "cmd/objdump/testdata/testfilenum", "cmd/pack", "cmd/pprof", "cmd/pprof/testdata", "cmd/test2json", "cmd/trace", "cmd/vendor", "cmd/vendor/github.com", "cmd/vendor/github.com/google", "cmd/vendor/github.com/google/pprof", "cmd/vendor/github.com/google/pprof/driver", "cmd/vendor/github.com/google/pprof/internal", "cmd/vendor/github.com/google/pprof/internal/binutils", "cmd/vendor/github.com/google/pprof/internal/driver", "cmd/vendor/github.com/google/pprof/internal/elfexec", "cmd/vendor/github.com/google/pprof/internal/graph", "cmd/vendor/github.com/google/pprof/internal/measurement", "cmd/vendor/github.com/google/pprof/internal/plugin", "cmd/vendor/github.com/google/pprof/internal/report", "cmd/vendor/github.com/google/pprof/internal/symbolizer", "cmd/vendor/github.com/google/pprof/internal/symbolz", "cmd/vendor/github.com/google/pprof/internal/transport", "cmd/vendor/github.com/google/pprof/profile", "cmd/vendor/github.com/google/pprof/third_party", "cmd/vendor/github.com/google/pprof/third_party/d3", "cmd/vendor/github.com/google/pprof/third_party/d3flamegraph", "cmd/vendor/github.com/google/pprof/third_party/svgpan", "cmd/vendor/github.com/ianlancetaylor", "cmd/vendor/github.com/ianlancetaylor/demangle", "cmd/vendor/golang.org", "cmd/vendor/golang.org/x", "cmd/vendor/golang.org/x/arch", "cmd/vendor/golang.org/x/arch/arm", "cmd/vendor/golang.org/x/arch/arm/armasm", "cmd/vendor/golang.org/x/arch/arm64", "cmd/vendor/golang.org/x/arch/arm64/arm64asm", "cmd/vendor/golang.org/x/arch/ppc64", "cmd/vendor/golang.org/x/arch/ppc64/ppc64asm", "cmd/vendor/golang.org/x/arch/x86", "cmd/vendor/golang.org/x/arch/x86/x86asm", "cmd/vendor/golang.org/x/crypto", "cmd/vendor/golang.org/x/crypto/ed25519", "cmd/vendor/golang.org/x/crypto/ed25519/internal", "cmd/vendor/golang.org/x/crypto/ed25519/internal/edwards25519", "cmd/vendor/golang.org/x/mod", "cmd/vendor/golang.org/x/mod/internal", "cmd/vendor/golang.org/x/mod/internal/lazyregexp", "cmd/vendor/golang.org/x/mod/modfile", "cmd/vendor/golang.org/x/mod/module", "cmd/vendor/golang.org/x/mod/semver", "cmd/vendor/golang.org/x/mod/sumdb", "cmd/vendor/golang.org/x/mod/sumdb/dirhash", "cmd/vendor/golang.org/x/mod/sumdb/note", "cmd/vendor/golang.org/x/mod/sumdb/tlog", "cmd/vendor/golang.org/x/mod/zip", "cmd/vendor/golang.org/x/sync", "cmd/vendor/golang.org/x/sync/semaphore", "cmd/vendor/golang.org/x/sys", "cmd/vendor/golang.org/x/sys/internal", "cmd/vendor/golang.org/x/sys/internal/unsafeheader", "cmd/vendor/golang.org/x/sys/plan9", "cmd/vendor/golang.org/x/sys/unix", "cmd/vendor/golang.org/x/sys/windows", "cmd/vendor/golang.org/x/term", "cmd/vendor/golang.org/x/tools", "cmd/vendor/golang.org/x/tools/cover", "cmd/vendor/golang.org/x/tools/go", "cmd/vendor/golang.org/x/tools/go/analysis", "cmd/vendor/golang.org/x/tools/go/analysis/internal", "cmd/vendor/golang.org/x/tools/go/analysis/internal/analysisflags", "cmd/vendor/golang.org/x/tools/go/analysis/internal/facts", "cmd/vendor/golang.org/x/tools/go/analysis/passes", "cmd/vendor/golang.org/x/tools/go/analysis/passes/asmdecl", "cmd/vendor/golang.org/x/tools/go/analysis/passes/assign", "cmd/vendor/golang.org/x/tools/go/analysis/passes/atomic", "cmd/vendor/golang.org/x/tools/go/analysis/passes/bools", "cmd/vendor/golang.org/x/tools/go/analysis/passes/buildtag", "cmd/vendor/golang.org/x/tools/go/analysis/passes/cgocall", "cmd/vendor/golang.org/x/tools/go/analysis/passes/composite", "cmd/vendor/golang.org/x/tools/go/analysis/passes/copylock", "cmd/vendor/golang.org/x/tools/go/analysis/passes/ctrlflow", "cmd/vendor/golang.org/x/tools/go/analysis/passes/errorsas", "cmd/vendor/golang.org/x/tools/go/analysis/passes/framepointer", "cmd/vendor/golang.org/x/tools/go/analysis/passes/httpresponse", "cmd/vendor/golang.org/x/tools/go/analysis/passes/ifaceassert", "cmd/vendor/golang.org/x/tools/go/analysis/passes/inspect", "cmd/vendor/golang.org/x/tools/go/analysis/passes/internal", "cmd/vendor/golang.org/x/tools/go/analysis/passes/internal/analysisutil", "cmd/vendor/golang.org/x/tools/go/analysis/passes/loopclosure", "cmd/vendor/golang.org/x/tools/go/analysis/passes/lostcancel", "cmd/vendor/golang.org/x/tools/go/analysis/passes/nilfunc", "cmd/vendor/golang.org/x/tools/go/analysis/passes/printf", "cmd/vendor/golang.org/x/tools/go/analysis/passes/shift", "cmd/vendor/golang.org/x/tools/go/analysis/passes/sigchanyzer", "cmd/vendor/golang.org/x/tools/go/analysis/passes/stdmethods", "cmd/vendor/golang.org/x/tools/go/analysis/passes/stringintconv", "cmd/vendor/golang.org/x/tools/go/analysis/passes/structtag", "cmd/vendor/golang.org/x/tools/go/analysis/passes/testinggoroutine", "cmd/vendor/golang.org/x/tools/go/analysis/passes/tests", "cmd/vendor/golang.org/x/tools/go/analysis/passes/unmarshal", "cmd/vendor/golang.org/x/tools/go/analysis/passes/unreachable", "cmd/vendor/golang.org/x/tools/go/analysis/passes/unsafeptr", "cmd/vendor/golang.org/x/tools/go/analysis/passes/unusedresult", "cmd/vendor/golang.org/x/tools/go/analysis/unitchecker", "cmd/vendor/golang.org/x/tools/go/ast", "cmd/vendor/golang.org/x/tools/go/ast/astutil", "cmd/vendor/golang.org/x/tools/go/ast/inspector", "cmd/vendor/golang.org/x/tools/go/cfg", "cmd/vendor/golang.org/x/tools/go/types", "cmd/vendor/golang.org/x/tools/go/types/objectpath", "cmd/vendor/golang.org/x/tools/go/types/typeutil", "cmd/vendor/golang.org/x/tools/internal", "cmd/vendor/golang.org/x/tools/internal/analysisinternal", "cmd/vendor/golang.org/x/tools/internal/lsp", "cmd/vendor/golang.org/x/tools/internal/lsp/fuzzy", "cmd/vendor/golang.org/x/tools/internal/typeparams", "cmd/vendor/golang.org/x/tools/txtar", "cmd/vendor/golang.org/x/xerrors", "cmd/vendor/golang.org/x/xerrors/internal", "cmd/vet", "cmd/vet/testdata", "cmd/vet/testdata/asm", "cmd/vet/testdata/assign", "cmd/vet/testdata/atomic", "cmd/vet/testdata/bool", "cmd/vet/testdata/buildtag", "cmd/vet/testdata/cgo", "cmd/vet/testdata/composite", "cmd/vet/testdata/copylock", "cmd/vet/testdata/deadcode", "cmd/vet/testdata/httpresponse", "cmd/vet/testdata/lostcancel", "cmd/vet/testdata/method", "cmd/vet/testdata/nilfunc", "cmd/vet/testdata/print", "cmd/vet/testdata/rangeloop", "cmd/vet/testdata/shift", "cmd/vet/testdata/structtag", "cmd/vet/testdata/tagtest", "cmd/vet/testdata/testingpkg", "cmd/vet/testdata/unmarshal", "cmd/vet/testdata/unsafeptr", "cmd/vet/testdata/unused", "compress", "compress/bzip2", "compress/bzip2/testdata", "compress/flate", "compress/flate/testdata", "compress/gzip", "compress/gzip/testdata", "compress/lzw", "compress/testdata", "compress/zlib", "container", "container/heap", "container/list", "container/ring", "context", "crypto", "crypto/aes", "crypto/cipher", "crypto/des", "crypto/dsa", "crypto/ecdsa", "crypto/ecdsa/testdata", "crypto/ed25519", "crypto/ed25519/internal", "crypto/ed25519/internal/edwards25519", "crypto/ed25519/internal/edwards25519/field", "crypto/ed25519/internal/edwards25519/field/_asm", "crypto/ed25519/testdata", "crypto/elliptic", "crypto/elliptic/internal", "crypto/elliptic/internal/fiat", "crypto/elliptic/internal/nistec", "crypto/hmac", "crypto/internal", "crypto/internal/randutil", "crypto/internal/subtle", "crypto/md5", "crypto/rand", "crypto/rc4", "crypto/rsa", "crypto/rsa/testdata", "crypto/sha1", "crypto/sha256", "crypto/sha512", "crypto/subtle", "crypto/tls", "crypto/tls/testdata", "crypto/x509", "crypto/x509/internal", "crypto/x509/internal/macos", "crypto/x509/pkix", "crypto/x509/testdata", "database", "database/sql", "database/sql/driver", "debug", "debug/buildinfo", "debug/dwarf", "debug/dwarf/testdata", "debug/elf", "debug/elf/testdata", "debug/gosym", "debug/gosym/testdata", "debug/macho", "debug/macho/testdata", "debug/pe", "debug/pe/testdata", "debug/plan9obj", "debug/plan9obj/testdata", "embed", "embed/internal", "embed/internal/embedtest", "embed/internal/embedtest/testdata", "embed/internal/embedtest/testdata/-not-hidden", "embed/internal/embedtest/testdata/.hidden", "embed/internal/embedtest/testdata/.hidden/.more", "embed/internal/embedtest/testdata/.hidden/_more", "embed/internal/embedtest/testdata/.hidden/more", "embed/internal/embedtest/testdata/_hidden", "embed/internal/embedtest/testdata/i", "embed/internal/embedtest/testdata/i/j", "embed/internal/embedtest/testdata/i/j/k", "encoding", "encoding/ascii85", "encoding/asn1", "encoding/base32", "encoding/base64", "encoding/binary", "encoding/csv", "encoding/gob", "encoding/hex", "encoding/json", "encoding/json/testdata", "encoding/pem", "encoding/xml", "errors", "expvar", "flag", "fmt", "go", "go/ast", "go/build", "go/build/constraint", "go/build/testdata", "go/build/testdata/cgo_disabled", "go/build/testdata/doc", "go/build/testdata/empty", "go/build/testdata/multi", "go/build/testdata/other", "go/build/testdata/other/file", "go/build/testdata/withvendor", "go/build/testdata/withvendor/src", "go/build/testdata/withvendor/src/a", "go/build/testdata/withvendor/src/a/b", "go/build/testdata/withvendor/src/a/vendor", "go/build/testdata/withvendor/src/a/vendor/c", "go/build/testdata/withvendor/src/a/vendor/c/d", "go/constant", "go/doc", "go/doc/testdata", "go/format", "go/importer", "go/internal", "go/internal/gccgoimporter", "go/internal/gccgoimporter/testdata", "go/internal/gcimporter", "go/internal/gcimporter/testdata", "go/internal/gcimporter/testdata/versions", "go/internal/srcimporter", "go/internal/srcimporter/testdata", "go/internal/srcimporter/testdata/issue20855", "go/internal/srcimporter/testdata/issue23092", "go/internal/srcimporter/testdata/issue24392", "go/internal/typeparams", "go/parser", "go/parser/testdata", "go/parser/testdata/issue42951", "go/parser/testdata/issue42951/not_a_file.go", "go/parser/testdata/resolution", "go/printer", "go/printer/testdata", "go/scanner", "go/token", "go/types", "go/types/testdata", "go/types/testdata/check", "go/types/testdata/check/decls2", "go/types/testdata/check/importdecl0", "go/types/testdata/check/importdecl1", "go/types/testdata/check/issue25008", "go/types/testdata/examples", "go/types/testdata/fixedbugs", "go/types/testdata/spec", "hash", "hash/adler32", "hash/crc32", "hash/crc64", "hash/fnv", "hash/maphash", "html", "html/template", "html/template/testdata", "image", "image/color", "image/color/palette", "image/draw", "image/gif", "image/internal", "image/internal/imageutil", "image/jpeg", "image/png", "image/png/testdata", "image/png/testdata/pngsuite", "image/testdata", "index", "index/suffixarray", "internal", "internal/abi", "internal/abi/testdata", "internal/buildcfg", "internal/bytealg", "internal/cfg", "internal/cpu", "internal/execabs", "internal/fmtsort", "internal/fuzz", "internal/goarch", "internal/godebug", "internal/goexperiment", "internal/goos", "internal/goroot", "internal/goversion", "internal/intern", "internal/itoa", "internal/lazyregexp", "internal/lazytemplate", "internal/nettrace", "internal/obscuretestdata", "internal/oserror", "internal/poll", "internal/profile", "internal/race", "internal/reflectlite", "internal/singleflight", "internal/syscall", "internal/syscall/execenv", "internal/syscall/unix", "internal/syscall/windows", "internal/syscall/windows/registry", "internal/syscall/windows/sysdll", "internal/sysinfo", "internal/testenv", "internal/testlog", "internal/trace", "internal/trace/testdata", "internal/unsafeheader", "internal/xcoff", "internal/xcoff/testdata", "io", "io/fs", "io/ioutil", "io/ioutil/testdata", "log", "log/syslog", "math", "math/big", "math/bits", "math/cmplx", "math/rand", "mime", "mime/multipart", "mime/multipart/testdata", "mime/quotedprintable", "mime/testdata", "net", "net/http", "net/http/cgi", "net/http/cgi/testdata", "net/http/cookiejar", "net/http/fcgi", "net/http/httptest", "net/http/httptrace", "net/http/httputil", "net/http/internal", "net/http/internal/ascii", "net/http/internal/testcert", "net/http/pprof", "net/http/testdata", "net/internal", "net/internal/socktest", "net/mail", "net/netip", "net/rpc", "net/rpc/jsonrpc", "net/smtp", "net/testdata", "net/textproto", "net/url", "os", "os/exec", "os/exec/internal", "os/exec/internal/fdtest", "os/signal", "os/signal/internal", "os/signal/internal/pty", "os/testdata", "os/testdata/dirfs", "os/testdata/dirfs/dir", "os/testdata/issue37161", "os/user", "path", "path/filepath", "plugin", "reflect", "reflect/internal", "reflect/internal/example1", "reflect/internal/example2", "regexp", "regexp/syntax", "regexp/testdata", "runtime", "runtime/asan", "runtime/cgo", "runtime/debug", "runtime/internal", "runtime/internal/atomic", "runtime/internal/math", "runtime/internal/sys", "runtime/internal/syscall", "runtime/metrics", "runtime/msan", "runtime/pprof", "runtime/pprof/testdata", "runtime/pprof/testdata/mappingtest", "runtime/race", "runtime/race/testdata", "runtime/testdata", "runtime/testdata/testfaketime", "runtime/testdata/testprog", "runtime/testdata/testprogcgo", "runtime/testdata/testprogcgo/windows", "runtime/testdata/testprognet", "runtime/testdata/testwinlib", "runtime/testdata/testwinlibsignal", "runtime/testdata/testwinsignal", "runtime/trace", "sort", "strconv", "strconv/testdata", "strings", "sync", "sync/atomic", "syscall", "syscall/js", "testdata", "testing", "testing/fstest", "testing/internal", "testing/internal/testdeps", "testing/iotest", "testing/quick", "text", "text/scanner", "text/tabwriter", "text/template", "text/template/parse", "text/template/testdata", "time", "time/testdata", "time/tzdata", "unicode", "unicode/utf16", "unicode/utf8", "unsafe", "vendor", "vendor/golang.org", "vendor/golang.org/x", "vendor/golang.org/x/crypto", "vendor/golang.org/x/crypto/chacha20", "vendor/golang.org/x/crypto/chacha20poly1305", "vendor/golang.org/x/crypto/cryptobyte", "vendor/golang.org/x/crypto/cryptobyte/asn1", "vendor/golang.org/x/crypto/curve25519", "vendor/golang.org/x/crypto/curve25519/internal", "vendor/golang.org/x/crypto/curve25519/internal/field", "vendor/golang.org/x/crypto/hkdf", "vendor/golang.org/x/crypto/internal", "vendor/golang.org/x/crypto/internal/poly1305", "vendor/golang.org/x/crypto/internal/subtle", "vendor/golang.org/x/net", "vendor/golang.org/x/net/dns", "vendor/golang.org/x/net/dns/dnsmessage", "vendor/golang.org/x/net/http", "vendor/golang.org/x/net/http/httpguts", "vendor/golang.org/x/net/http/httpproxy", "vendor/golang.org/x/net/http2", "vendor/golang.org/x/net/http2/hpack", "vendor/golang.org/x/net/idna", "vendor/golang.org/x/net/lif", "vendor/golang.org/x/net/nettest", "vendor/golang.org/x/net/route", "vendor/golang.org/x/sys", "vendor/golang.org/x/sys/cpu", "vendor/golang.org/x/text", "vendor/golang.org/x/text/secure", "vendor/golang.org/x/text/secure/bidirule", "vendor/golang.org/x/text/transform", "vendor/golang.org/x/text/unicode", "vendor/golang.org/x/text/unicode/bidi", "vendor/golang.org/x/text/unicode/norm", ""}
