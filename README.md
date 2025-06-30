# sslscan

sslscan is a comprehensive SSL/TLS security scanner written in Go. It scans servers for supported protocols, cipher suites, certificate analysis, and known vulnerabilities such as Heartbleed and CRIME.

## Features
- Detects supported SSL/TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
- Lists and analyzes cipher suites
- Performs certificate validation and analysis
- Checks for known vulnerabilities (Heartbleed, CRIME, etc.)
- Outputs results in console, XML, and JUnit formats

## Usage

```sh
# Basic scan
sslscan example.com

# Scan with custom port and output
sslscan --port 8443 --xml results.xml example.com

# Verbose scan with JUnit output
sslscan --junit results.xml --verbose example.com
```

## Build

```sh
make build
```

Or with Docker:

```sh
docker build -t sslscan .
docker run --rm sslscan --help
```

## Running Tests

```sh
make test
```

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## License

MIT 
