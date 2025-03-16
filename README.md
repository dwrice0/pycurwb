# Project Title

pycurwb Python library

## Description

pycurwb is a Python library created for decoding Cisco URWB telemetry packets using scapy.  Based on URWB Telemetry Protocol 2.0.19.  This is intended to make easy for development of a wrapper around this library to process the telemetry.  A basic sample program is included that dumps the decoded packets to the screen.

## Getting Started

### Dependencies

* scapy is required specifically for the library
* typer is required for the demo program

### Executing demo program

* Install pre-requisites
```
pip install scapy typer
```
* To capture on Windows interface Ethernet 3 and udp port 1234
```
capture.py --interface "Ethernet 3" --port 12345
```

## Help

Check out the demo program help for available options
```
capture.py --help
```

## Authors

David Rice  
@wiguy80211

## Version History

* 0.1
    * Initial Release

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details

## References

* [Cisco URWB Telemetry Protocol 2.0.19](https://www.cisco.com/c/en/us/td/docs/wireless/outdoor_industrial/iw9167/reference/URWB_Telemetry_Protocol_2-0-19.html)
* [Scapy project page](https://scapy.readthedocs.io/en/latest/index.html)
* [Typer project page](https://typer.tiangolo.com/)

## Disclaimer

* This project is not affiliated with Cisco Systems, Inc.
