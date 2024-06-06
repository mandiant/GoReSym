# Inlined Function Identification

This file describes the process of identifying functions that have been inlined by the Go compiler. 
It also details how this process is implemented in GoReSym and lists known TODOs.

## Finding []runtime__inlinedCall

These steps calculate where to find the inline tree for a function `f` . 
The inline tree holds information about any and all functions that were inlined into `f` by the Go compiler.
The documentation implies that each function that contains inlined functions will have its own distinct tree.

1. Choose a function `f`
2. Get `funcData` for `f`.
3. Check whether `funcData.funcdata[FUNCDATA_InlTree]` exists (want `funcData.nfuncdata` >= `FUNCDATA_InlTree`)
4. Check whether `funcData.funcdata[FUNCDATA_InlTree]` is valid (want `funcData.funcdata[FUNCDATA_InlTree]` != `^uint32(0)`)
5. Save `funcData.funcdata[FUNCDATA_InlTree]` -- this is the inline tree offset for `f`
6. Get `go:func.*` via `moduledata`. (there are other ways but this is the least complicated)
7. Adjust `go:func.*` from absolute address to file offset by subtracting the preferred base address (in file header). `go:func.* -= baseAddress`
9. Go to inline tree. InlineTreeAddress = `go:func.*` + `funcData.funcdata[FUNCDATA_InlTree]`.

   *NOTE: the inline tree and `go:func.*` addresses may be earlier in the binary than `pclntab`*
   Therefore whatever component resolves inline functions MUST have access to the full file.

## Resolving a single runtime__inlinedCall



## Known issues

### How to calculate size of inline tree for a given `f`.

Right now we start at a function's inline tree base and
process inline call data until we hit invalid data. If two inline trees for functions `f` and `j` are next to each other
with no buffer then `j`'s tree will be mistakenly included in `f`'s tree. The functions that were inlined into `j` 
will be listed twice as inlined inside `f` as well as `j`. 

### Using pcdata

We don't currently use `funcData.pcdata[PCDATA_InlineTreeIndex]`. 
Use `funcData.pcdata[PCDATA_InlineTreeIndex]` + `pcHeader.pctabOffset` to go to relevant offset in `pcdata`. 
(N.B. Some docs call `pcdata` the `pctab`. These are distinct from `pclntab`.)
The inline tree index could be used to check whether any given PC in a function kicks off inlined function instructions. 
Since we want every inlined function and are not iterating over every PC in every function, we're not currently using this. HOWEVER. 
This info might be helpful in determining how many functions were inlined into `f`. We would then be able to separate inline trees.


## References

[pclntab structs reference](https://github.com/elastic/otel-profiling-agent/blob/main/docs/gopclntab.md)
