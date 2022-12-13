# Contributing

## Building from Source (Linux / macOS)

### Prerequisites
* [git](https://git-scm.com/)
* [make](https://www.gnu.org/software/make/)
* [go >= 1.18](https://go.dev/doc/install)


### Ubuntu / Debian
```bash
sudo apt install git make golang-go libcap-dev
```

### Arch
```bash
sudo pacman -S git make go
```

### macOS
```bash
brew install git make go
```

## Steps
To build **gofuzz** from source you have to execute the following steps:
```bash
git clone https://github.com/CodeIntelligenceTesting/gofuzz.git
cd gofuzz
make test
make build
```

If everything went fine, you will find the newly created directory
`./build/bin` which includes the gofuzz CLI.

## Adding new bug detectors
Bug detectors implement the `Detector` interface.
```go
type Detector interface {
    Detect() error
}
```
The `Detect` function performs checks to detect specific classes of bugs and returns 
specialized errors representing the found bugs. The function can also guide the fuzzer
towards producing interesting inputs that trigger the bugs of interest. You can have a 
look at [the existing bug detectors](https://github.com/CodeIntelligenceTesting/gofuzz/tree/main/sanitizers/detectors).
for more details.
### Guiding the fuzzer
Bug detectors often look for certain patterns in the arguments passed to the hooked 
functions or methods. To work effectively, they can provide hints to the fuzzer so that
it produces inputs containing these patterns. The [fuzzer](https://github.com/CodeIntelligenceTesting/gofuzz/tree/main/sanitizers/fuzzer) 
provides an API to achieve that. It has the following functions:
 * `GuideTowardsEquality` guides the fuzzer to produce a string that is equal to a target string.
 * `GuideTowardsContainment` guides the fuzzer to produce a string containing a target string.
