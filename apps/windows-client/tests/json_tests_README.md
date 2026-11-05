# JSON parser regression gates

The parser source and GNU/Linux tests passed independent scoped review. This is
not full credential/service acceptance and does not replace supported Microsoft
STL runtime evidence.

## CTest modes

With `BUILD_TESTING=ON`, the client registers required `json-zeroization`,
`json-transfer`, and `json-inplace_semantic` tests. Ordinary builds default to
allocation-release auditing; the positive control must work before the audit can
pass. Sanitizer configuration flags disable the allocation hooks and label that
run `semantic-only`; it must not be reported as dirty-free auditing. Explicitly
select `-DORANGESPACE_JSON_ALLOCATION_AUDIT=OFF` for any sanitizer setup whose flags
are supplied outside the CMake variables inspected by the target.

```sh
cmake -S . -B "$TMPDIR/json-tests" -DCMAKE_BUILD_TYPE=Release
cmake --build "$TMPDIR/json-tests" --target orangespace-json-zeroization-tests orangespace-json-transfer-tests orangespace-json-inplace_semantic-tests
ctest --test-dir "$TMPDIR/json-tests" -R '^json-' --output-on-failure
```

GNU/Linux transfer observation requires function instrumentation, no inlining,
exported symbols and `dladdr`; the CMake target supplies those flags. Compiling
that standalone test without its documented flags deliberately fails its positive
control. On Windows it prints move traits and exercises semantics without claiming
the GNU transfer observer. Neither GNU's traits nor a cross-build prove Microsoft
STL behavior. Run allocation auditing on the actual supported Windows STL,
including nested-map allocation failures/valueless-variant cleanup, before closing
that platform gate.

## Compatibility and limits

`Value` still exposes the same variant alternatives, copying, `.data`, `.find`,
`.text` and ordinary alternative-brace construction. It is **no longer an
aggregate**: external designated initializers/aggregate-trait users require
migration. No such consumers were found in this repository during scoped review.

Successful secret-bearing DOMs still require caller wiping. Caller-owned DOM
copies/transfers, source inputs, allocator internals, registers and OS copies are
outside this parser-owned cleanup claim. The input/depth limits remain unchanged;
there is no new independent DOM-entry/allocation budget. A 1 MiB input can allocate
substantially more than 1 MiB. Adding a tighter resource budget is a separate
scope decision, not something these tests silently enable.
