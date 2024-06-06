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
9. Go to inline tree. InlineTreeAddress = `go:func.*` + `funcData.funcdata[FUNCDATA_InlTree]`.  This is an offset relative to the start of the binary file because we adjusted `go:func.*` in step 7 above.

   *NOTE: the inline tree and `go:func.*` addresses may be earlier in the binary than `pclntab`*
   Therefore whatever component resolves inline functions MUST have access to the full file.

## Validating inline tree entries

We iterate from the InlineTreeAddress, grab enough bytes to fill a single `runtime__inlinedCall` instance. Validate its fields. If any validation check fails or there are not enough bytes to fill the struct, assume that we have reached the end of the tree. Return results.

```
Start at InlineTreeAddress.
While there are at least sizeof(runtime__inlinedCall) bytes not yet checked:
  Get sizeof(runtime__inlinedCall) bytes as potentialCall
  Check potentialCall.funcID
      - funcID must be 0 (i.e. "normal")
      - the subsequent padding bytes must also be 0 (number of pad bytes depends on Go version)
      - if these fail, break
  Check potentialCall.parentPc
      - get parentFunction.Entry (aka start offset) (we have this data in the funcData used to locate the inline tree)
      - get parentFunction.End (aka end offset)
      - potentialCall.parentPc + parentFunction.Entry must be less than parentFunction.End
      - if parentPc falls beyond the end of parentFunction, break
  Check potentialCall.name (the field name varies between Go versions)
      - get pcHeader.funcNameOffset
      - get size in bytes of function name table
      - pcHeader.funcNameOffset + potentialCall.name must fall within bounds of the function name table
      - [NOT IMPLEMENTED] first char must be ASCII, previous char should be 0 (null-terminator)
      - if name offset is invalid, break
  Save data from the runtime__inlinedCall struct into a version-agnostic InlinedCall object
  Add the new InlinedCall object to array of found InlinedCall objects
  Move forward by sizeof(runtime_inlinedCall)

Return array of InlinedCall objects   

```

## Known issues

### Not implemented yet for Go v1.11-1.18

### Only tested on ELF format

### Saving inlined function names

Currently we manually calculate the size of the string to creat the slice. There's gotta be a better way to save the string and probably some extra validation we could to make sure that the func name offset points to the start of a string.

### Only processing inlined calls where funcID==0 (normal function)

Haven't found a great description of the funcID types. We may want to include more than just normal functions. We might also find that each inline tree ends with inline info for a type. If we can find a description of the inline tree or trees section as a whole, then we might be able to use this as a pattern to separate where inline trees begin/end.

### How to calculate size of inline tree for a given `f`.

Right now we start at a function's inline tree base and
process inline call data until we hit invalid data. If two inline trees for functions `f` and `j` are next to each other
with no buffer then `j`'s tree will be mistakenly included in `f`'s tree. The functions that were inlined into `j` 
will be listed twice as inlined inside `f` as well as `j`. 

Another heuristic to help could be checking the tree bases for all functions with inline data and stopping the inline struct iteration when we reach another function's tree base. 

Haven't found any overview of an "inlined data section". Either finding one or walking through the compiler steps to build one would be useful.

### Using pcdata

We don't currently use `funcData.pcdata[PCDATA_InlineTreeIndex]`. 
Use `funcData.pcdata[PCDATA_InlineTreeIndex]` + `pcHeader.pctabOffset` to go to relevant offset in `pcdata`. 
(N.B. Some docs call `pcdata` the `pctab`. These are distinct from `pclntab`.)
The inline tree index could be used to check whether any given PC in a function kicks off inlined function instructions. 
Since we want every inlined function and are not iterating over every PC in every function, we're not currently using this. HOWEVER. 
This info might be helpful in determining how many functions were inlined into `f`. We would then be able to separate inline trees.


## References

* [pclntab structs reference](https://github.com/elastic/otel-profiling-agent/blob/main/docs/gopclntab.md)
* [adding inline functions for golang debugger](https://developers.redhat.com/articles/2024/04/03/how-add-debug-support-go-stripped-binaries)
* [how and why inlining with source examples](https://dave.cheney.net/2020/04/25/inlining-optimisations-in-go)
