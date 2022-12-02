<div align="center">
  <h1>gofuzz</h1>
  <p>Bug detectors for Golang</p>
  <a href="https://github.com/CodeIntelligenceTesting/gofuzz/actions/workflows/run-all-tests.yml">
    <img src="https://img.shields.io/github/workflow/status/CodeIntelligenceTesting/gofuzz/Tests%20and%20Linting?logo=github" />
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
**gofuzz** is a CLI tool to add bug detection capabilities into your Go code. It transforms the source code and replace calls to functions/methods of interests by calls to corresponding hooks in the `github.com/CodeIntelligenceTesting/gofuzz/sanitizers` module. **gofuzz** does not change the code in-place, but generates the instrumented source code in a temporary directory and produces an [overlay file](https://go.dev/doc/go1.16) that can be used by your build tools