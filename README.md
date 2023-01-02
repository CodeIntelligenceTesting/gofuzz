<div align="center">
  <h1>gofuzz</h1>
  <p>Bug detectors for Golang</p>
  <a href="https://github.com/CodeIntelligenceTesting/gofuzz/actions/workflows/run-all-tests.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/CodeIntelligenceTesting/gofuzz/run-all-tests.yml?branch=main&logo=github" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/gofuzz/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/gofuzz/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/CodeIntelligenceTesting/gofuzz" />
  </a>
  <br />

<a href="https://www.code-intelligence.com/" target="_blank">Website</a>
|
<a href="https://www.code-intelligence.com/blog" target="_blank">Blog</a>
|
<a href="https://twitter.com/CI_Fuzz" target="_blank">Twitter</a>

</div>

## gofuzz

**gofuzz** is a CLI tool to add bug detection capabilities into your Go code.
It transforms the source code and replaces calls to functions/methods of interest by calls to corresponding hooks in the `github.com/CodeIntelligenceTesting/gofuzz/sanitizers` module.
**gofuzz** does not change the code in-place, but generates the instrumented source code in a temporary directory.
It produces an [overlay file](https://go.dev/doc/go1.16) that can be used by Go's standard build tools.

## How to use

1. (Once) Install the **gofuzz** CLI

   ```shell
   go install github.com/CodeIntelligenceTesting/gofuzz/cmd/gofuzz@latest
   ```

   The minimum required Golang version is Go 1.18.

2. (Once) Add the **sanitizers** package as a dependency for the code base you want to test.
   This package contains the implementation of the hooks inserted by **gofuzz** into your code,
   and therefore must be available when the instrumented code is being compiled.

   ```shell
   cd <my project>
   go get -u github.com/CodeIntelligenceTesting/gofuzz/sanitizers@latest
   ```

   This command also adds the **sanitizers** package as a dependency in the `go.mod` file.
3. Instrument your code using the **sanitize** subcommand

   ```shell
   gofuzz sanitize <package> -o <overlay.json>
   ```

   This instruments the specified package and writes the instrumented file into a temporary
   directory. The corresponding file replacements are stored in the <overlay.json> file.
   By default, **gofuzz** writes a file named overlay.json in the current directory.

4. Instrument your code for fuzzing using [go114-fuzz-build](https://github.com/kyakdan/go114-fuzz-build).
   Note that we use a fork of the original [repo](https://github.com/mdempsky/go114-fuzz-build)
   because we need a change that has not yet been merged upstream.

   ```shell
   go114-fuzz-build -o target.a -func <fuzz_test> -overlay <overlay.json> <package>
   ```

   This tool uses the host Go to instrument the code using the libFuzzer mode. We recommend using
   a Go version later than 1.19 as it contains [several improvements](https://www.code-intelligence.com/blog/golang-fuzzing-1.19) to make fuzzing considerably more effective.

5. Link the created archive with libFuzzer

   ```shell
   clang -fsanitize=fuzzer target.a -o fuzzer
   ```

6. Run the fuzzer

   ```shell
   ./fuzzer [fuzzer args]
   ```
