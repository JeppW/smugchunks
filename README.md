# smugchunks
smugchunks is a black-box scanner for HTTP request smuggling vulnerabilities caused by chunk parser differentials. Using timeout-based probes, it detects exploitable inconsistencies between front-end and back-end interpretations of chunked-coding HTTP requests.

This tool is in no way an alternative to the amazing [Smuggler](https://github.com/defparam/smuggler) by [defparam](https://github.com/defparam), and the two tools perform no overlapping checks. Rather, it is intended to be its complement; whereas Smuggler identifies inconsistencies in the interpretation of the `Content-Length` and `Transfer-Encoding` headers, smugchunks identifies inconsistencies in the interpretation of the chunked message body itself.

For an introduction to the techniques that this tool is based on, see the accompanying blog post [here](https://w4ke.info/2025/06/18/funky-chunks.html).

## Installation and usage
To get started, simply clone this repository, install the dependencies, and run the Python script.

```
$ git clone https://github.com/JeppW/smugchunks && cd smugchunks
$ pip install -r requirements.txt
$ python3 smugchunks.py --url https://example.com --method GET --output findings.txt
```

You must supply either a single URL through the `--url` parameter or a list of URLs through the `--input-file` parameter. See `python3 smugchunks.py --help` for more command-line options. 

smugchunks only *identifies* vulnerabilities - it is not an exploitation tool. That part is up to you. If you're not sure how to exploit these kinds of request smuggling vulnerabilities, take a look at Ben Kallus's and Prashant Anantharaman's [ShmooCon talk](https://youtube.com/watch?v=aKPAX00ft5s&t=2h19m0s) or my own [blog post](https://w4ke.info/2025/06/18/funky-chunks.html).

## Request smuggling techniques
Currently, smugchunks performs checks for the following vulnerabilities:

- __TERM.EXT and EXT.TERM__: Discrepancies in the parsing of line terminators in chunk extensions.

- __TERM.SPILL and SPILL.TERM__: Discrepancies in the parsing of line terminators in oversized chunks.

I would like to add tests pertaining to inconsistencies in the integer parsing of chunk sizes, but I haven't been able to figure out how to detect such vulnerabilities blindly. If you know of a reliable way to identify such vulnerabilities, feel free to [reach out](mailto:jeppe.b.weikop@gmail.com) or submit a PR. 

## A note on false positives
I'd love to tell you that smugchunks doesn't produce false positives. Unfortunately, that would be a lie. I've gone to great lengths to eliminate them, and in my experience they're really quite rare. Still, it does happen. You should therefore always manually verify each finding from this tool before taking action; don't report scan results to bug bounty programs.

On a side note, if smugchunks consistently reports an issue that turns out to be a false positive, it probably means the front-end is doing some questionable HTTP parsing. Even if it's not exploitable in the way smugchunks expects, that parsing behavior could still be dangerous - definitely something worth digging into.

## Acknowledgements
The timeout-based detection techniques that power smugchunks have been adapted from those introduced by [James Kettle](https://jameskettle.com/) in 2019.

The request smuggling techniques supported by smugchunks are in part based on work by [Matthias Grenfeldt](https://grenfeldt.dev/), Asta Olofsson, [Ben Kallus](https://kallus.org/) and [Prashant Anantharaman](https://prashant.at/). 
