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
